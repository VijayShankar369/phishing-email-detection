"""
Flask Web Application for AI-Powered Phishing Email Detection System.

Features:
- Email text analysis (POST /analyze) with real-time accuracy tracking
- File upload analysis (GET/POST /upload)
- Analytics endpoints (/api/stats, /api/health, /api/accuracy/*)
- User feedback for model correction (/feedback)
- Dashboard and basic UI routes
- Graceful handling when optional components (DB, preprocessor, predictor) are unavailable
"""

import os
import hashlib
import logging
import traceback
from datetime import datetime
from typing import Optional

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    flash,
)
from werkzeug.utils import secure_filename

# Local project imports - adjust as needed
from src.accuracy_tracker import accuracy_tracker
from src.prediction import PhishingPredictor
from src.database import DatabaseManager
from src.data_preprocessing import EmailPreprocessor
from config import Config

# -----------------------------------------------------------------------------
# App init & config
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

# Ensure a secret key is set for sessions
app.secret_key = getattr(Config, "SECRET_KEY", os.environ.get("SECRET_KEY", "dev-secret-key"))

# Ensure upload folder exists
UPLOAD_FOLDER = app.config.get("UPLOAD_FOLDER", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Allowed extensions
DEFAULT_ALLOWED = {"txt", "eml", "msg"}
ALLOWED_EXTENSIONS = set(app.config.get("ALLOWED_EXTENSIONS", DEFAULT_ALLOWED))

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Initialize optional components (predictor, db, preprocessor)
# -----------------------------------------------------------------------------
predictor: Optional[PhishingPredictor] = None
db_manager: Optional[DatabaseManager] = None
preprocessor: Optional[EmailPreprocessor] = None

try:
    predictor = PhishingPredictor(model_dir=getattr(Config, "MODEL_DIR", "data/models"))
    logger.info("✅ Predictor loaded successfully")
except Exception as e:
    logger.error(f"❌ Failed to load predictor: {e}")
    logger.error(traceback.format_exc())

try:
    db_manager = DatabaseManager()
    logger.info("✅ Database manager loaded successfully")
except Exception as e:
    logger.error(f"❌ Failed to load database manager: {e}")
    logger.error(traceback.format_exc())

try:
    preprocessor = EmailPreprocessor()
    logger.info("✅ Preprocessor loaded successfully")
except Exception as e:
    logger.error(f"❌ Failed to load preprocessor: {e}")
    logger.error(traceback.format_exc())

logger.info("Application initialization completed")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    """Check if the uploaded file has an allowed extension."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def get_client_ip() -> str:
    """Get client IP address - respects X-Forwarded-For when behind proxies."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # X-Forwarded-For may contain a list: take first
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def log_activity(action: str, **kwargs) -> None:
    """Log user activity to database if db_manager is available."""
    if not db_manager:
        return
    try:
        db_manager.log_user_activity(
            session_id=session.get("session_id"),
            action=action,
            ip_address=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
            **kwargs,
        )
    except Exception as e:
        logger.warning(f"Failed to log activity: {e}")


@app.before_request
def ensure_session():
    """Ensure session has an ID to correlate actions."""
    if "session_id" not in session:
        seed = f"{datetime.utcnow().isoformat()}|{get_client_ip()}"
        session["session_id"] = hashlib.md5(seed.encode()).hexdigest()


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    """Main page with brief statistics (7 days)."""
    log_activity("page_visit")
    stats = {}
    if db_manager:
        try:
            stats = db_manager.get_prediction_statistics(days=7)
        except Exception as e:
            logger.warning(f"Failed to fetch stats: {e}")
    return render_template("index.html", stats=stats)


@app.route("/analyze", methods=["POST"])
def analyze_email():
    """
    Analyze email content for phishing (single endpoint).
    Returns prediction JSON structure from predictor + email_hash.
    Tracks prediction in accuracy_tracker (if available).
    """
    try:
        if not predictor:
            logger.error("Predictor not available")
            return jsonify({"error": "Prediction system unavailable"}), 503

        # Accept JSON or form-encoded input
        email_text = ""
        if request.is_json:
            data = request.get_json(silent=True) or {}
            email_text = data.get("email_text", "")
        else:
            email_text = request.form.get("email_text", "")

        if email_text is None:
            email_text = ""
        email_text = email_text.strip()

        if not email_text:
            return jsonify({"error": "Please provide email content"}), 400

        max_length = getattr(Config, "MAX_EMAIL_LENGTH", 10000)
        if len(email_text) > max_length:
            return jsonify({"error": f"Email too long. Max length: {max_length} characters"}), 400

        # Create short hash for tracking/feedback
        full_hash = hashlib.sha256(email_text.encode()).hexdigest()
        email_hash_short = full_hash[:10]

        logger.info(f"Analyzing email (length: {len(email_text)}, hash: {email_hash_short})")
        log_activity("email_analysis_attempt", email_hash=email_hash_short)

        # Run prediction
        prediction = predictor.predict_single_email(email_text)
        # Defensive: ensure expected keys exist
        if "ensemble_prediction" not in prediction:
            logger.warning("prediction missing 'ensemble_prediction' key; wrapping result")
            prediction = {"ensemble_prediction": {"label": str(prediction)}}

        # Track in real-time accuracy tracker if available
        try:
            if hasattr(accuracy_tracker, "add_prediction"):
                # Expect accuracy_tracker.add_prediction(prediction, confidence, email_hash)
                ep = prediction.get("ensemble_prediction", {})
                accuracy_tracker.add_prediction(
                    prediction=ep.get("prediction", ep.get("label")),
                    confidence=ep.get("confidence", None),
                    email_hash=email_hash_short,
                )
        except Exception as e:
            logger.warning(f"Failed to add prediction to accuracy tracker: {e}")

        logger.info(f"Prediction completed: {prediction['ensemble_prediction'].get('label')}")

        # Add email hash to response for later feedback
        prediction["email_hash"] = email_hash_short

        # Attempt to store in database (non-fatal)
        if db_manager and preprocessor:
            try:
                email_data = preprocessor.extract_email_content(email_text)
                email_data["processed_text"] = preprocessor.preprocess_text(email_text)
                email_id = db_manager.store_email(email_data)
                db_manager.store_prediction(email_id, prediction)
                log_activity("email_analysis", prediction=prediction["ensemble_prediction"].get("label"))
            except Exception as e:
                logger.warning(f"Failed to store prediction in database: {e}")

        return jsonify(prediction)

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    """Upload a file containing an email (txt/eml/msg) and analyze it."""
    if request.method == "GET":
        return render_template("upload.html")

    try:
        if not predictor:
            flash("Prediction system unavailable", "error")
            return redirect(url_for("upload_file"))

        file = request.files.get("file")
        if not file or file.filename == "":
            flash("No file selected", "error")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash(f"Allowed file types: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "error")
            return redirect(request.url)

        # Build secure filename with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        safe_name = secure_filename(file.filename)
        filename = f"{timestamp}_{safe_name}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        # Save file
        file.save(filepath)

        try:
            # Read file content (ignore binary errors)
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if not content.strip():
                flash("Uploaded file appears empty or unreadable", "error")
                return redirect(request.url)

            prediction = predictor.predict_single_email(content)

            # Store file analysis in DB if available (non-fatal)
            if db_manager and preprocessor:
                try:
                    email_data = preprocessor.extract_email_content(content)
                    email_data["processed_text"] = preprocessor.preprocess_text(content)
                    email_id = db_manager.store_email(email_data)
                    db_manager.store_prediction(email_id, prediction)
                    log_activity(
                        "file_analysis",
                        filename=filename,
                        prediction=prediction["ensemble_prediction"].get("label"),
                    )
                except Exception as e:
                    logger.warning(f"Failed to store file analysis in database: {e}")

            # Render result template with prediction and original filename
            return render_template("result.html", prediction=prediction, filename=file.filename)

        except Exception as e:
            logger.error(f"File analysis error: {e}")
            logger.error(traceback.format_exc())
            flash("Error analyzing file", "error")
            return redirect(request.url)

        finally:
            # Clean up the uploaded file
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception:
                logger.warning(f"Failed to remove temporary file: {filepath}")

    except Exception as e:
        logger.error(f"Upload error: {e}")
        logger.error(traceback.format_exc())
        flash("Upload failed", "error")
        return redirect(request.url)


# -----------------------------------------------------------------------------
# APIs: stats, health, accuracy, feedback
# -----------------------------------------------------------------------------
@app.route("/api/stats")
def api_stats():
    """API endpoint returning statistics, recent predictions, and model performance."""
    try:
        if not db_manager:
            return jsonify({"error": "Database unavailable"}), 503

        days = request.args.get("days", 30, type=int)
        stats = db_manager.get_prediction_statistics(days=days)
        recent = db_manager.get_recent_predictions(limit=10)
        perf = db_manager.get_model_performance()
        return jsonify({"statistics": stats, "recent_predictions": recent, "model_performance": perf})
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Error retrieving stats"}), 500


@app.route("/api/health")
def api_health():
    """Health check endpoint for basic components."""
    status = {
        "predictor": predictor is not None,
        "database": db_manager is not None,
        "preprocessor": preprocessor is not None,
        "timestamp": datetime.utcnow().isoformat(),
    }
    # Only predictor is essential for 'healthy'
    all_healthy = status["predictor"]
    return jsonify({"status": "healthy" if all_healthy else "degraded", "components": status}), (
        200 if all_healthy else 503
    )


@app.route("/api/accuracy/live")
def get_live_accuracy():
    """Return real-time accuracy statistics from accuracy_tracker."""
    try:
        hours = request.args.get("hours", 24, type=int)
        if not hasattr(accuracy_tracker, "get_real_time_stats"):
            return jsonify({"error": "Accuracy tracker not available"}), 503
        stats = accuracy_tracker.get_real_time_stats(hours=hours)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Live accuracy API error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Failed to get accuracy data"}), 500


@app.route("/api/accuracy/trend")
def get_accuracy_trend():
    """Return accuracy trend data (days)."""
    try:
        days = request.args.get("days", 7, type=int)
        if not hasattr(accuracy_tracker, "get_accuracy_trend"):
            return jsonify({"error": "Accuracy tracker not available"}), 503
        trend = accuracy_tracker.get_accuracy_trend(days=days)
        return jsonify({"trend": trend})
    except Exception as e:
        logger.error(f"Accuracy trend API error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Failed to get trend data"}), 500


@app.route("/feedback", methods=["POST"])
def submit_feedback():
    """
    Accept user feedback to correct model predictions.
    Expected JSON: { "email_hash": "<short-hash>", "actual_label": 0|1 }
    """
    try:
        data = request.get_json(silent=True) or {}
        email_hash = data.get("email_hash")
        actual_label = data.get("actual_label")

        if not email_hash or actual_label is None:
            return jsonify({"error": "Missing email_hash or actual_label"}), 400

        if not hasattr(accuracy_tracker, "add_user_feedback"):
            return jsonify({"error": "Accuracy tracker not available"}), 503

        success = accuracy_tracker.add_user_feedback(email_hash=email_hash, actual_label=int(actual_label), feedback="user_correction")

        if success:
            logger.info(f"User feedback added for {email_hash}: {actual_label}")
            return jsonify({"message": "Feedback recorded successfully"})
        else:
            return jsonify({"error": "Could not find prediction to update"}), 404

    except Exception as e:
        logger.error(f"Feedback error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Failed to record feedback"}), 500


# -----------------------------------------------------------------------------
# Dashboard and misc pages
# -----------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    """Dashboard page with more complete stats (requires DB)."""
    try:
        if not db_manager:
            flash("Dashboard data unavailable. Database not connected.", "error")
            return redirect(url_for("index"))

        stats = db_manager.get_prediction_statistics(days=30)
        recent_predictions = db_manager.get_recent_predictions(limit=20)
        model_performance = db_manager.get_model_performance()
        return render_template(
            "dashboard.html",
            stats=stats,
            recent_predictions=recent_predictions,
            model_performance=model_performance,
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        logger.error(traceback.format_exc())
        flash("Failed to load dashboard data", "error")
        return redirect(url_for("index"))


@app.route("/accuracy-dashboard")
def accuracy_dashboard():
    """Render a front-end for live accuracy visualization."""
    return render_template("accuracy_dashboard.html")


# -----------------------------------------------------------------------------
# Error handlers & test route
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template("error.html", error_code=404, error_message="Page Not Found"), 404


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {e}")
    logger.error(traceback.format_exc())
    return render_template("error.html", error_code=500, error_message="Internal Server Error"), 500


@app.route("/test")
def test():
    """Simple health summary for quick checks."""
    return jsonify(
        {
            "status": "ok",
            "predictor_loaded": predictor is not None,
            "db_loaded": db_manager is not None,
            "preprocessor_loaded": preprocessor is not None,
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


# -----------------------------------------------------------------------------
# App runner
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Change to script directory for relative template/static paths
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("🚀 Starting Flask application...")
    print(f"📁 Working directory: {os.getcwd()}")
    print(f"🤖 Predictor loaded: {'✅' if predictor else '❌'}")
    print(f"🗄️  Database loaded: {'✅' if db_manager else '❌'}")
    print(f"⚙️  Preprocessor loaded: {'✅' if preprocessor else '❌'}")

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=getattr(Config, "DEBUG", True),
        use_reloader=getattr(Config, "DEBUG", True),
    )
