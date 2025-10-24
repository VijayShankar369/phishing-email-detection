import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'replace-with-your-secret-key')
    DEBUG      = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    # Database Configuration
    DB_HOST     = os.environ.get('DB_HOST', 'localhost')
    DB_USER     = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'password')
    DB_NAME     = os.environ.get('DB_NAME', 'phishing_detection')

    # Encode password for URI
    ENCODED_DB_PASSWORD = quote_plus(DB_PASSWORD)

    # SQLAlchemy URI
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+mysqlconnector://{DB_USER}:{ENCODED_DB_PASSWORD}@"
        f"{DB_HOST}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload Settings
    UPLOAD_FOLDER      = os.path.join(os.getcwd(), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS = {'txt', 'eml', 'msg'}

    # Model Paths - FIXED to match training script output
    MODEL_DIR               = os.path.join(os.getcwd(), 'data', 'models')
    TFIDF_VECTORIZER_PATH   = os.path.join(MODEL_DIR, 'tfidf_vectorizer.pkl')
    RANDOM_FOREST_MODEL_PATH= os.path.join(MODEL_DIR, 'random_forest_model.pkl')
    SVM_MODEL_PATH          = os.path.join(MODEL_DIR, 'svm_model.pkl')
    SVM_SCALER_PATH         = os.path.join(MODEL_DIR, 'svm_scaler.pkl')
    FEATURE_NAMES_PATH      = os.path.join(MODEL_DIR, 'feature_names.txt')

    # Feature Extraction - matches training script
    MAX_FEATURES = 3000
    MIN_DF       = 2
    MAX_DF       = 0.95
    NGRAM_RANGE  = (1, 2)
    SUBLINEAR_TF = True

    # Email Limits
    MAX_EMAIL_LENGTH = 10000

    # Suspicious Indicators
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'verify', 'suspended', 'click here', 'limited time',
        'act now', 'congratulations', 'winner', 'lottery', 'prize',
        'free money', 'guaranteed', 'risk free', 'no obligation',
        'dear sir/madam', 'dear customer', 'update payment',
        'confirm identity', 'account suspended', 'security alert'
    ]

    SUSPICIOUS_URL_PATTERNS = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r't\.co',   # URL shorteners
        r'\d+\.\d+\.\d+\.\d+',                              # IP-based URLs
        r'[a-z]+\d+[a-z]+\.com'                             # Mixed alphanumeric domains
    ]

    # Additional settings for better compatibility
    TESTING = False
    CSRF_ENABLED = True
    WTF_CSRF_ENABLED = True
