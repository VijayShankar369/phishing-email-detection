"""
Flask web application for AI-Powered Phishing Email Detection System.
Provides a user-friendly interface for email analysis and file uploads.
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import hashlib
import logging
from datetime import datetime
import pandas as pd
import json

# Import our custom modules
from src.prediction import PhishingPredictor
from src.database import DatabaseManager
from src.data_preprocessing import EmailPreprocessor
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize components
try:
    predictor = PhishingPredictor()
    db_manager = DatabaseManager()
    preprocessor = EmailPreprocessor()
    logger.info("Application components initialized successfully")
except Exception as e:
    logger.error(f"Error initializing components: {str(e)}")
    predictor = None
    db_manager = None
    preprocessor = None

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    """Check if uploaded file is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_session_id():
    """Generate unique session ID."""
    if 'session_id' not in session:
        session['session_id'] = hashlib.md5(
            f"{datetime.now()}{request.environ.get('REMOTE_ADDR')}".encode()
        ).hexdigest()
    return session['session_id']

def get_client_ip():
    """Get client IP address."""
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))

@app.route('/')
def index():
    """Main page with email input form."""
    generate_session_id()
    
    # Log user activity
    if db_manager:
        try:
            db_manager.log_user_activity(
                session_id=session['session_id'],
                action='page_visit',
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent')
            )
        except Exception as e:
            logger.error(f"Error logging user activity: {str(e)}")
    
    # Get recent statistics for display
    stats = {}
    if db_manager:
        try:
            stats = db_manager.get_prediction_statistics(days=7)
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
    
    return render_template('index.html', stats=stats)

@app.route('/analyze', methods=['POST'])
def analyze_email():
    """Analyze email content for phishing detection."""
    if not predictor:
        return jsonify({
            'error': 'Prediction system not available. Please contact administrator.'
        }), 500
    
    try:
        email_text = request.form.get('email_text', '').strip()
        
        if not email_text:
            return jsonify({'error': 'Please provide email content to analyze.'}), 400
        
        if len(email_text) > app.config['MAX_EMAIL_LENGTH']:
            return jsonify({
                'error': f'Email content too long. Maximum {app.config["MAX_EMAIL_LENGTH"]} characters allowed.'
            }), 400
        
        # Generate email content hash
        email_hash = hashlib.sha256(email_text.encode()).hexdigest()
        
        # Extract email data
        email_data = preprocessor.extract_email_content(email_text)
        email_data['processed_text'] = preprocessor.preprocess_text(email_text)
        
        # Make prediction
        prediction_result = predictor.predict_single_email(email_text)
        
        # Store in database
        try:
            email_id = db_manager.store_email(email_data)
            db_manager.store_prediction(email_id, prediction_result)
            
            # Log user activity
            db_manager.log_user_activity(
                session_id=session['session_id'],
                action='email_analysis',
                prediction_result=prediction_result['ensemble_prediction']['label'],
                email_hash=email_hash,
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent')
            )
        except Exception as e:
            logger.error(f"Error storing results: {str(e)}")
        
        # Prepare response
        response_data = {
            'success': True,
            'prediction': prediction_result['ensemble_prediction'],
            'individual_predictions': prediction_result['individual_predictions'],
            'email_analysis': prediction_result['email_analysis'],
            'timestamp': prediction_result['timestamp']
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        return jsonify({
            'error': 'An error occurred while analyzing the email. Please try again.'
        }), 500

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file uploads for email analysis."""
    if request.method == 'GET':
        return render_template('upload.html')
    
    if not predictor:
        flash('Prediction system not available. Please contact administrator.', 'error')
        return redirect(url_for('upload_file'))
    
    try:
        if 'file' not in request.files:
            flash('No file selected for upload.', 'error')
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected for upload.', 'error')
            return redirect(url_for('upload_file'))
        
        if not allowed_file(file.filename):
            flash(f'File type not allowed. Allowed types: {", ".join(app.config["ALLOWED_EXTENSIONS"])}', 'error')
            return redirect(url_for('upload_file'))
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()
        except Exception as e:
            flash(f'Error reading file: {str(e)}', 'error')
            os.remove(file_path)  # Clean up
            return redirect(url_for('upload_file'))
        
        # Analyze email
        prediction_result = predictor.predict_single_email(email_content)
        
        # Extract email data
        email_data = preprocessor.extract_email_content(email_content)
        email_data['processed_text'] = preprocessor.preprocess_text(email_content)
        
        # Store results
        try:
            email_id = db_manager.store_email(email_data)
            db_manager.store_prediction(email_id, prediction_result)
            
            # Log user activity
            db_manager.log_user_activity(
                session_id=session['session_id'],
                action='file_upload_analysis',
                prediction_result=prediction_result['ensemble_prediction']['label'],
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent')
            )
        except Exception as e:
            logger.error(f"Error storing file analysis results: {str(e)}")
        
        # Clean up uploaded file
        os.remove(file_path)
        
        return render_template('result.html', 
                             prediction=prediction_result,
                             filename=file.filename)
        
    except Exception as e:
        logger.error(f"Error in file upload: {str(e)}")
        flash('An error occurred while processing the file. Please try again.', 'error')
        return redirect(url_for('upload_file'))

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics."""
    if not db_manager:
        return jsonify({'error': 'Database not available'}), 500
    
    try:
        days = request.args.get('days', 30, type=int)
        stats = db_manager.get_prediction_statistics(days=days)
        recent_predictions = db_manager.get_recent_predictions(limit=10)
        model_performance = db_manager.get_model_performance()
        
        return jsonify({
            'statistics': stats,
            'recent_predictions': recent_predictions,
            'model_performance': model_performance
        })
    except Exception as e:
        logger.error(f"Error getting API stats: {str(e)}")
        return jsonify({'error': 'Error retrieving statistics'}), 500

@app.route('/api/health')
def api_health():
    """Health check endpoint."""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'predictor': predictor is not None,
            'database': db_manager is not None,
            'preprocessor': preprocessor is not None
        }
    }
    
    # Check if models are loaded
    if predictor:
        model_info = predictor.get_model_info()
        health_status['components']['models'] = model_info['available_models']
    
    # Overall health
    all_healthy = all(health_status['components'].values())
    health_status['status'] = 'healthy' if all_healthy else 'degraded'
    
    status_code = 200 if all_healthy else 503
    return jsonify(health_status), status_code

@app.route('/dashboard')
def dashboard():
    """Analytics dashboard."""
    if not db_manager:
        flash('Database not available for dashboard.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get statistics
        stats = db_manager.get_prediction_statistics(days=30)
        recent_predictions = db_manager.get_recent_predictions(limit=20)
        model_performance = db_manager.get_model_performance()
        
        return render_template('dashboard.html',
                             stats=stats,
                             recent_predictions=recent_predictions,
                             model_performance=model_performance)
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash('Error loading dashboard data.', 'error')
        return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return render_template('error.html', 
                         error_code=404,
                         error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return render_template('error.html',
                         error_code=500,
                         error_message="Internal server error"), 500

@app.errorhandler(413)
def file_too_large_error(error):
    """Handle file too large errors."""
    return render_template('error.html',
                         error_code=413,
                         error_message="File too large"), 413

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('data/models', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)