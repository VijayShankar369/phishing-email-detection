# Configuration settings for the Phishing Email Detection System
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Database Configuration
    DATABASE_CONFIG = {
        'host': os.environ.get('DB_HOST') or 'localhost',
        'user': os.environ.get('DB_USER') or 'root',
        'password': os.environ.get('DB_PASSWORD') or 'password',
        'database': os.environ.get('DB_NAME') or 'phishing_detection'
    }
    
    # Encode password to handle special characters like '@'
    ENCODED_DB_PASSWORD = quote_plus(DATABASE_CONFIG['password'])
    
    # MySQL Database URI with encoded password
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+mysqlconnector://{DATABASE_CONFIG['user']}:{ENCODED_DB_PASSWORD}@"
        f"{DATABASE_CONFIG['host']}/{DATABASE_CONFIG['database']}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File Upload Configuration
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'eml', 'msg'}
    
    # Model Configuration
    MODEL_PATH = 'data/models/'
    VECTORIZER_PATH = 'data/models/tfidf_vectorizer.pkl'
    RANDOM_FOREST_MODEL_PATH = 'data/models/random_forest_model.pkl'
    SVM_MODEL_PATH = 'data/models/svm_model.pkl'
    
    # Feature Extraction Configuration
    MAX_FEATURES = 5000
    MIN_DF = 2
    MAX_DF = 0.95
    NGRAM_RANGE = (1, 2)
    
    # Email Processing Configuration
    MAX_EMAIL_LENGTH = 10000
    SUSPICIOUS_KEYWORDS = [
        'urgent', 'verify', 'suspended', 'click here', 'limited time',
        'act now', 'congratulations', 'winner', 'lottery', 'prize',
        'free money', 'guaranteed', 'risk free', 'no obligation',
        'dear sir/madam', 'dear customer', 'update payment',
        'confirm identity', 'account suspended', 'security alert'
    ]
    
    # URL Patterns for Detection
    SUSPICIOUS_URL_PATTERNS = [
        r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r't\.co',
        r'\d+\.\d+\.\d+\.\d+',  # IP addresses
        r'[a-z]+\d+[a-z]+\.com',  # Mixed alphanumeric domains
    ]
