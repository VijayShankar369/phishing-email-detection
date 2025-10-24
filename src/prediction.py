"""
Enhanced Prediction module for phishing email detection.
Updated to work with Config file and new trained models.
"""

import os
import re
import joblib
import logging
import pandas as pd
import numpy as np
from datetime import datetime
from config import Config

class PhishingPredictor:
    """Real-time phishing email predictor using ensemble machine learning."""

    def __init__(self, model_dir=None):
        self.model_dir = model_dir or Config.MODEL_DIR
        self.models = {}
        self.vectorizer = None
        self.scaler = None
        self.feature_names = []
        self.logger = logging.getLogger(__name__)
        self._load_models()

    def _load_models(self):
        """Load trained models and preprocessing components."""
        try:
            # Define model files with correct paths from config
            model_files = {
                'random_forest': Config.RANDOM_FOREST_MODEL_PATH,
                'svm': Config.SVM_MODEL_PATH,
                'scaler': Config.SVM_SCALER_PATH,
                'vectorizer': Config.TFIDF_VECTORIZER_PATH
            }
            
            # Load each model file
            for name, file_path in model_files.items():
                if os.path.exists(file_path):
                    if name == 'scaler':
                        self.scaler = joblib.load(file_path)
                    elif name == 'vectorizer':
                        self.vectorizer = joblib.load(file_path)
                    else:
                        self.models[name] = joblib.load(file_path)
                    self.logger.info(f"✅ Loaded {name} from {os.path.basename(file_path)}")
                else:
                    self.logger.error(f"❌ Model file not found: {file_path}")
                    raise FileNotFoundError(f"Required model file not found: {file_path}")

            # Load feature names
            feature_path = getattr(Config, 'FEATURE_NAMES_PATH', 
                                 os.path.join(self.model_dir, 'feature_names.txt'))
            if os.path.exists(feature_path):
                with open(feature_path, 'r', encoding='utf-8') as f:
                    self.feature_names = [line.strip() for line in f.readlines()]
                self.logger.info(f"✅ Loaded {len(self.feature_names)} feature names")
            else:
                self.logger.warning("⚠️ Feature names file not found - this may cause issues")

            self.logger.info("🎉 All models loaded successfully!")

        except Exception as e:
            self.logger.error(f"❌ Error loading models: {e}")
            raise

    def preprocess_text(self, text):
        """Simple but effective text preprocessing - matches training exactly"""
        try:
            # Convert to lowercase
            text = str(text).lower()
            
            # Remove special characters but keep spaces
            text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
            
            # Remove extra whitespace
            text = ' '.join(text.split())
            
            return text
        except Exception as e:
            self.logger.error(f"Text preprocessing error: {e}")
            return ""

    def extract_features(self, email_text):
        """Extract features exactly as done in training"""
        try:
            # Preprocess text
            processed_text = self.preprocess_text(email_text)
            
            # TF-IDF features
            if not self.vectorizer:
                raise ValueError("TF-IDF vectorizer not loaded")
                
            tfidf_features = self.vectorizer.transform([processed_text])
            tfidf_dense = tfidf_features.toarray()
            
            # Create feature DataFrame with correct column names
            tfidf_feature_names = [f"tfidf_{i}" for i in range(tfidf_dense.shape[1])]
            feature_df = pd.DataFrame(tfidf_dense, columns=tfidf_feature_names)
            
            # Extract metadata features (exact same as training)
            metadata = {
                'email_length': len(email_text),
                'word_count': len(email_text.split()),
                'url_count': email_text.count('http'),
                'exclamation_count': email_text.count('!'),
                'question_count': email_text.count('?'),
                'dollar_count': email_text.count('$'),
                'urgent_words': sum(1 for word in ['urgent', 'immediate', 'asap', 'hurry'] 
                                   if word.lower() in email_text.lower()),
                'suspicious_keywords': sum(1 for word in ['verify', 'click', 'suspended', 'limited', 'expires'] 
                                         if word.lower() in email_text.lower())
            }
            
            # Add metadata to feature DataFrame
            for key, value in metadata.items():
                feature_df[key] = value
            
            # If we have feature names from training, ensure consistency
            if self.feature_names:
                # Add missing features with zeros
                for feature_name in self.feature_names:
                    if feature_name not in feature_df.columns:
                        feature_df[feature_name] = 0
                
                # Reorder to match training order
                feature_df = feature_df[self.feature_names]
            
            self.logger.info(f"✅ Extracted {len(feature_df.columns)} features (expected: {len(self.feature_names)})")
            return feature_df.values
            
        except Exception as e:
            self.logger.error(f"❌ Feature extraction error: {e}")
            raise

    def predict_single_email(self, email_text):
        """Predict if email is phishing using ensemble approach."""
        try:
            if not email_text or not email_text.strip():
                raise ValueError("Email text is empty")
            
            # Extract features
            features = self.extract_features(email_text)
            
            # Initialize results
            results = {}
            
            # Random Forest prediction
            if 'random_forest' in self.models:
                rf_pred = int(self.models['random_forest'].predict(features)[0])
                rf_proba = self.models['random_forest'].predict_proba(features)[0]
                
                results['random_forest'] = {
                    'prediction': rf_pred,
                    'label': 'Phishing' if rf_pred else 'Legitimate',
                    'confidence': float(rf_proba[rf_pred]),
                    'probabilities': {
                        'legitimate': float(rf_proba[0]),
                        'phishing': float(rf_proba[1])
                    }
                }
            
            # SVM prediction
            if 'svm' in self.models and self.scaler:
                features_scaled = self.scaler.transform(features)
                svm_pred = int(self.models['svm'].predict(features_scaled)[0])
                svm_proba = self.models['svm'].predict_proba(features_scaled)[0]
                
                results['svm'] = {
                    'prediction': svm_pred,
                    'label': 'Phishing' if svm_pred else 'Legitimate',
                    'confidence': float(svm_proba[svm_pred]),
                    'probabilities': {
                        'legitimate': float(svm_proba[0]),
                        'phishing': float(svm_proba[1])
                    }
                }
            
            # Ensemble decision
            if 'random_forest' in results and 'svm' in results:
                rf_pred = results['random_forest']['prediction']
                svm_pred = results['svm']['prediction']
                
                # Simple voting - prefer Random Forest if disagreement
                final_pred = rf_pred
                confidence = results['random_forest']['confidence']
                agreement = rf_pred == svm_pred
                
                ensemble = {
                    'prediction': int(final_pred),
                    'label': 'Phishing' if final_pred else 'Legitimate',
                    'confidence': float(confidence),
                    'agreement': agreement
                }
            else:
                # Fallback if only one model available
                primary_result = results.get('random_forest') or results.get('svm')
                ensemble = {
                    'prediction': primary_result['prediction'],
                    'label': primary_result['label'],
                    'confidence': primary_result['confidence'],
                    'agreement': True
                }
            
            # Email analysis
            email_analysis = self._analyze_email_content(email_text)
            
            self.logger.info(f"🎯 Prediction: {ensemble['label']} (confidence: {ensemble['confidence']:.3f})")
            
            return {
                'individual_predictions': results,
                'ensemble_prediction': ensemble,
                'email_analysis': email_analysis,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"❌ Prediction error: {e}")
            raise

    def _analyze_email_content(self, text):
        """Analyze email content for suspicious indicators."""
        try:
            urls = re.findall(r'http[s]?://\S+', text)
            indicators = []
            score = 0

            if urls:
                indicators.append(f"Contains {len(urls)} URL(s)")
                score += len(urls) * 10

            # Check for suspicious keywords from config
            found_keywords = []
            for keyword in Config.SUSPICIOUS_KEYWORDS:
                if keyword.lower() in text.lower():
                    found_keywords.append(keyword)
            
            if found_keywords:
                indicators.append(f"Suspicious keywords: {', '.join(found_keywords[:5])}")
                score += len(found_keywords) * 8

            return {
                'suspicious_indicators': indicators,
                'risk_score': min(score, 100),
                'statistics': {
                    'character_count': len(text),
                    'word_count': len(text.split()),
                    'url_count': len(urls),
                    'suspicious_keyword_count': len(found_keywords)
                }
            }
        except Exception as e:
            self.logger.error(f"❌ Email analysis error: {e}")
            return {
                'suspicious_indicators': [],
                'risk_score': 0,
                'statistics': {'character_count': 0, 'word_count': 0, 'url_count': 0}
            }
