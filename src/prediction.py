"""
Prediction module for phishing email detection.
Handles real-time email classification and analysis.
"""

import joblib
import pandas as pd
import numpy as np
import logging
from datetime import datetime
import os
import re
from src.data_preprocessing import EmailPreprocessor
from src.feature_extraction import FeatureExtractor


class PhishingPredictor:
    """
    Real-time phishing email prediction system.
    """
    
    def __init__(self, model_dir='data/models/'):
        """
        Initialize the predictor with trained models.
        
        Args:
            model_dir (str): Directory containing trained models
        """
        self.model_dir = model_dir
        self.models = {}
        self.vectorizer = None
        self.feature_extractor = None
        self.preprocessor = EmailPreprocessor()
        self.logger = logging.getLogger(__name__)
        
        # Load models and components
        self.load_models()
        
    def load_models(self):
        """Load trained models and preprocessing components."""
        try:
            # Load Random Forest model
            rf_path = os.path.join(self.model_dir, 'random_forest_model.pkl')
            if os.path.exists(rf_path):
                self.models['random_forest'] = joblib.load(rf_path)
                self.logger.info("Random Forest model loaded successfully")
            
            # Load SVM model
            svm_path = os.path.join(self.model_dir, 'svm_model.pkl')
            if os.path.exists(svm_path):
                self.models['svm'] = joblib.load(svm_path)
                self.logger.info("SVM model loaded successfully")
            
            # Load TF-IDF vectorizer
            vectorizer_path = os.path.join(self.model_dir, 'tfidf_vectorizer.pkl')
            if os.path.exists(vectorizer_path):
                self.vectorizer = joblib.load(vectorizer_path)
                self.logger.info("TF-IDF vectorizer loaded successfully")
            
            # Initialize feature extractor with loaded vectorizer
            self.feature_extractor = FeatureExtractor()
            if self.vectorizer:
                self.feature_extractor.tfidf_vectorizer = self.vectorizer
                self.feature_extractor.feature_names = self.vectorizer.get_feature_names_out()
            
            if not self.models:
                self.logger.error("No models loaded. Please train models first.")
                
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            raise
    
    def predict_single_email(self, email_text, return_probabilities=True):
        """
        Predict if a single email is phishing or legitimate.
        
        Args:
            email_text (str): Raw email content
            return_probabilities (bool): Whether to return prediction probabilities
            
        Returns:
            dict: Prediction results
        """
        if not self.models:
            raise ValueError("No models available. Please load or train models first.")
        
        try:
            # Preprocess the email
            processed_text = self.preprocessor.preprocess_text(email_text)
            
            # Create a DataFrame for feature extraction
            df = pd.DataFrame({
                'text': [email_text],
                'processed_text': [processed_text]
            })
            
            # Extract features
            features, _ = self.feature_extractor.extract_all_features(df, fit=False)
            
            # Make predictions with all available models
            predictions = {}
            
            for model_name, model in self.models.items():
                prediction = model.predict(features)[0]
                predictions[model_name] = {
                    'prediction': int(prediction),
                    'label': 'Phishing' if prediction == 1 else 'Legitimate'
                }
                
                if return_probabilities and hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(features)[0]
                    predictions[model_name]['probabilities'] = {
                        'legitimate': float(proba[0]),
                        'phishing': float(proba[1])
                    }
                    predictions[model_name]['confidence'] = float(max(proba))
            
            # Ensemble prediction (majority voting)
            ensemble_prediction = self._ensemble_predict(predictions)
            
            # Extract additional email analysis
            email_analysis = self._analyze_email_content(email_text)
            
            return {
                'individual_predictions': predictions,
                'ensemble_prediction': ensemble_prediction,
                'email_analysis': email_analysis,
                'processed_text': processed_text,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {str(e)}")
            raise
    
    def _ensemble_predict(self, predictions):
        """
        Create ensemble prediction from individual model predictions.
        
        Args:
            predictions (dict): Individual model predictions
            
        Returns:
            dict: Ensemble prediction result
        """
        # Majority voting
        phishing_votes = sum(1 for pred in predictions.values() if pred['prediction'] == 1)
        total_votes = len(predictions)
        
        ensemble_prediction = 1 if phishing_votes > total_votes / 2 else 0
        ensemble_label = 'Phishing' if ensemble_prediction == 1 else 'Legitimate'
        
        # Average confidence
        confidences = [pred.get('confidence', 0.5) for pred in predictions.values()]
        average_confidence = np.mean(confidences) if confidences else 0.5
        
        return {
            'prediction': ensemble_prediction,
            'label': ensemble_label,
            'confidence': float(average_confidence),
            'votes': f"{phishing_votes}/{total_votes}",
            'agreement': all(pred['prediction'] == ensemble_prediction for pred in predictions.values())
        }
    
    def _analyze_email_content(self, email_text):
        """
        Analyze email content for suspicious indicators.
        
        Args:
            email_text (str): Raw email content
            
        Returns:
            dict: Email analysis results
        """
        analysis = {
            'suspicious_indicators': [],
            'risk_score': 0,
            'statistics': {}
        }
        
        # Extract email structure
        email_data = self.preprocessor.extract_email_content(email_text)
        
        # Basic statistics
        analysis['statistics'] = {
            'character_count': len(email_text),
            'word_count': len(email_text.split()),
            'url_count': len(email_data.get('urls', [])),
            'sender': email_data.get('sender_email', 'Unknown')
        }
        
        # Check for suspicious indicators
        risk_score = 0
        
        # URL analysis
        if email_data.get('urls'):
            analysis['suspicious_indicators'].append(f"Contains {len(email_data['urls'])} URL(s)")
            risk_score += len(email_data['urls']) * 10
            
            # Check for suspicious URL patterns
            for url in email_data['urls']:
                if re.search(r'\d+\.\d+\.\d+\.\d+', url):  # IP address
                    analysis['suspicious_indicators'].append("Contains IP address URL")
                    risk_score += 20
                
                if any(domain in url.lower() for domain in ['bit.ly', 'tinyurl.com', 'goo.gl']):
                    analysis['suspicious_indicators'].append("Contains shortened URL")
                    risk_score += 15
        
        # Keyword analysis
        suspicious_keywords = [
            'urgent', 'verify', 'suspended', 'click here', 'limited time',
            'act now', 'congratulations', 'winner', 'lottery', 'prize'
        ]
        
        found_keywords = [kw for kw in suspicious_keywords if kw in email_text.lower()]
        if found_keywords:
            analysis['suspicious_indicators'].append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
            risk_score += len(found_keywords) * 5
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediate', 'asap', 'hurry', 'deadline', 'expires']
        urgency_count = sum(1 for word in urgency_words if word in email_text.lower())
        if urgency_count > 0:
            analysis['suspicious_indicators'].append(f"Contains {urgency_count} urgency indicator(s)")
            risk_score += urgency_count * 8
        
        # Excessive punctuation
        exclamation_count = email_text.count('!')
        if exclamation_count > 3:
            analysis['suspicious_indicators'].append(f"Excessive exclamation marks ({exclamation_count})")
            risk_score += exclamation_count * 2
        
        # Sender analysis
        sender_email = email_data.get('sender_email')
        if sender_email:
            if re.search(r'[0-9]+@', sender_email):
                analysis['suspicious_indicators'].append("Suspicious sender address pattern")
                risk_score += 15
            
            if any(pattern in sender_email.lower() for pattern in ['noreply', 'donotreply']):
                analysis['suspicious_indicators'].append("Generic sender address")
                risk_score += 5
        
        # Normalize risk score (cap at 100)
        analysis['risk_score'] = min(risk_score, 100)
        
        return analysis
    
    def predict_batch_emails(self, email_list):
        """
        Predict multiple emails at once.
        
        Args:
            email_list (list): List of email texts
            
        Returns:
            list: List of prediction results
        """
        results = []
        
        for i, email_text in enumerate(email_list):
            try:
                result = self.predict_single_email(email_text)
                result['email_index'] = i
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error processing email {i}: {str(e)}")
                results.append({
                    'email_index': i,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return results
    
    def predict_from_file(self, file_path):
        """
        Predict phishing for emails from a file.
        
        Args:
            file_path (str): Path to file containing email content
            
        Returns:
            dict: Prediction result
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                email_content = file.read()
            return self.predict_single_email(email_content)
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {str(e)}")
            raise
    
    def get_model_info(self):
        """
        Get information about loaded models.
        
        Returns:
            dict: Model information
        """
        info = {
            'available_models': list(self.models.keys()),
            'vectorizer_loaded': self.vectorizer is not None,
            'model_details': {}
        }
        
        for model_name, model in self.models.items():
            info['model_details'][model_name] = {
                'type': type(model).__name__,
                'parameters': model.get_params()
            }
        
        return info

def create_predictor_from_trained_models(model_dir='data/models/'):
    """
    Create a predictor instance with trained models.
    
    Args:
        model_dir (str): Directory containing trained models
        
    Returns:
        PhishingPredictor: Configured predictor
    """
    return PhishingPredictor(model_dir)

if __name__ == "__main__":
    # Example usage
    sample_phishing_email = """
    Subject: URGENT: Your Account Will Be Suspended

    Dear Customer,

    We have detected suspicious activity on your account. Your account will be 
    suspended in 24 hours unless you verify your information immediately.

    Click here to verify: http://fake-bank.com/verify?id=12345

    Act now to avoid losing access to your account!

    Customer Service Team
    """

    sample_legitimate_email = """
    Subject: Meeting Reminder - Project Review Tomorrow

    Hi Team,

    This is a reminder about our project review meeting scheduled for tomorrow 
    at 2:00 PM in Conference Room B.

    Please bring your progress reports and any materials you'd like to discuss.

    Best regards,
    John Smith
    Project Manager
    """

    try:
        # Create predictor
        predictor = PhishingPredictor()
        
        # Test predictions
        print("Testing phishing email:")
        result1 = predictor.predict_single_email(sample_phishing_email)
        print(f"Prediction: {result1['ensemble_prediction']['label']}")
        print(f"Confidence: {result1['ensemble_prediction']['confidence']:.2f}")
        
        print("\nTesting legitimate email:")
        result2 = predictor.predict_single_email(sample_legitimate_email)
        print(f"Prediction: {result2['ensemble_prediction']['label']}")
        print(f"Confidence: {result2['ensemble_prediction']['confidence']:.2f}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Please ensure models are trained and saved first.")
