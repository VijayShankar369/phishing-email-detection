"""
Database operations module for phishing email detection system.
Handles email storage, prediction logging, and analytics.
"""

import mysql.connector
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import pandas as pd
import numpy as np
import logging
from config import Config

Base = declarative_base()

class EmailRecord(Base):
    """Email record model for database storage."""
    __tablename__ = 'emails'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sender_email = Column(String(255))
    sender_name = Column(String(255))
    receiver_email = Column(String(255))
    subject = Column(Text)
    body = Column(Text)
    processed_text = Column(Text)
    urls = Column(Text)  # JSON string of URLs
    timestamp = Column(DateTime, default=datetime.utcnow)
    
class PredictionRecord(Base):
    """Prediction record model for database storage."""
    __tablename__ = 'predictions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer)  # Foreign key to emails table (add ForeignKey if needed)
    model_name = Column(String(50))
    prediction = Column(Integer)  # 0 = legitimate, 1 = phishing
    prediction_label = Column(String(20))
    confidence = Column(Float)
    probability_legitimate = Column(Float)
    probability_phishing = Column(Float)
    risk_score = Column(Float)
    suspicious_indicators = Column(Text)  # JSON string
    timestamp = Column(DateTime, default=datetime.utcnow)

class UserActivity(Base):
    """User activity tracking for web interface."""
    __tablename__ = 'user_activity'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100))
    action = Column(String(50))
    email_content_hash = Column(String(64))
    prediction_result = Column(String(20))
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45))
    user_agent = Column(Text)

class DatabaseManager:
    """Database manager for phishing detection system."""
    
    def __init__(self):
        """Initialize database connection and setup."""
        self.engine = None
        self.Session = None
        self.logger = logging.getLogger(__name__)
        self.setup_database()
    
    def setup_database(self):
        """Setup database connection and create tables."""
        try:
            # Create database engine
            self.engine = create_engine(
                Config.SQLALCHEMY_DATABASE_URI,
                echo=False,
                pool_recycle=3600
            )
            
            # Create session factory
            self.Session = sessionmaker(bind=self.engine)
            
            # Create tables
            Base.metadata.create_all(self.engine)
            
            self.logger.info("Database setup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Database setup failed: {str(e)}")
            raise
    
    def get_session(self):
        """Get a new database session."""
        return self.Session()
    
    def store_email(self, email_data):
        """
        Store email data in the database.
        
        Args:
            email_data (dict): Email data dictionary
            
        Returns:
            int: Email record ID
        """
        session = self.get_session()
        try:
            email_record = EmailRecord(
                sender_email=email_data.get('sender_email', ''),
                sender_name=email_data.get('sender_name', ''),
                receiver_email=email_data.get('receiver', ''),
                subject=email_data.get('subject', ''),
                body=email_data.get('body', ''),
                processed_text=email_data.get('processed_text', ''),
                urls=str(email_data.get('urls', []))  # Convert list to string
            )
            session.add(email_record)
            session.commit()
            email_id = email_record.id
            self.logger.info(f"Email stored with ID: {email_id}")
            return email_id
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Error storing email: {str(e)}")
            raise
        finally:
            session.close()
    
    def store_prediction(self, email_id, prediction_data):
        """
        Store prediction result in the database.
        
        Args:
            email_id (int): Email record ID
            prediction_data (dict): Prediction result data
        """
        session = self.get_session()
        try:
            # Store individual model predictions
            for model_name, pred_result in prediction_data['individual_predictions'].items():
                prediction_record = PredictionRecord(
                    email_id=email_id,
                    model_name=model_name,
                    prediction=pred_result['prediction'],
                    prediction_label=pred_result['label'],
                    confidence=pred_result.get('confidence', 0.0),
                    probability_legitimate=pred_result.get('probabilities', {}).get('legitimate', 0.0),
                    probability_phishing=pred_result.get('probabilities', {}).get('phishing', 0.0),
                    risk_score=prediction_data['email_analysis'].get('risk_score', 0.0),
                    suspicious_indicators=str(prediction_data['email_analysis'].get('suspicious_indicators', []))
                )
                session.add(prediction_record)
            
            # Store ensemble prediction
            ensemble_pred = prediction_data['ensemble_prediction']
            ensemble_record = PredictionRecord(
                email_id=email_id,
                model_name='ensemble',
                prediction=ensemble_pred['prediction'],
                prediction_label=ensemble_pred['label'],
                confidence=ensemble_pred['confidence'],
                probability_legitimate=0.0,
                probability_phishing=0.0,
                risk_score=prediction_data['email_analysis'].get('risk_score', 0.0),
                suspicious_indicators=str(prediction_data['email_analysis'].get('suspicious_indicators', []))
            )
            session.add(ensemble_record)
            
            session.commit()
            self.logger.info(f"Predictions stored for email ID: {email_id}")
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Error storing predictions: {str(e)}")
            raise
        finally:
            session.close()
    
    def log_user_activity(self, session_id, action, prediction_result=None, 
                          email_hash=None, ip_address=None, user_agent=None):
        """
        Log user activity for analytics.
        
        Args:
            session_id (str): User session ID
            action (str): Action performed
            prediction_result (str): Prediction result if applicable
            email_hash (str): Hash of email content
            ip_address (str): User IP address
            user_agent (str): User agent string
        """
        session = self.get_session()
        try:
            activity_record = UserActivity(
                session_id=session_id,
                action=action,
                email_content_hash=email_hash,
                prediction_result=prediction_result,
                ip_address=ip_address,
                user_agent=user_agent
            )
            session.add(activity_record)
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Error logging user activity: {str(e)}")
        finally:
            session.close()
    
    def get_prediction_statistics(self, days=30):
        """
        Get prediction statistics for the last N days.
        
        Args:
            days (int): Number of days to look back
            
        Returns:
            dict: Statistics dictionary
        """
        session = self.get_session()
        try:
            cutoff_date = datetime.utcnow() - pd.Timedelta(days=days)
            predictions = session.query(PredictionRecord).filter(
                PredictionRecord.timestamp >= cutoff_date,
                PredictionRecord.model_name == 'ensemble'
            ).all()
            
            if not predictions:
                return {
                    'total_predictions': 0,
                    'phishing_detected': 0,
                    'legitimate_emails': 0,
                    'phishing_rate': 0.0,
                    'average_confidence': 0.0,
                    'high_risk_emails': 0
                }
            
            total_predictions = len(predictions)
            phishing_detected = sum(1 for p in predictions if p.prediction == 1)
            legitimate_emails = total_predictions - phishing_detected
            phishing_rate = (phishing_detected / total_predictions) * 100
            average_confidence = np.mean([p.confidence for p in predictions])
            high_risk_emails = sum(1 for p in predictions if p.risk_score > 70)
            
            return {
                'total_predictions': total_predictions,
                'phishing_detected': phishing_detected,
                'legitimate_emails': legitimate_emails,
                'phishing_rate': round(phishing_rate, 2),
                'average_confidence': round(average_confidence, 3),
                'high_risk_emails': high_risk_emails
            }
        except Exception as e:
            self.logger.error(f"Error getting statistics: {str(e)}")
            return {}
        finally:
            session.close()
    
    def get_recent_predictions(self, limit=50):
        """
        Get recent prediction results.
        
        Args:
            limit (int): Number of recent predictions to retrieve
            
        Returns:
            list: List of recent predictions
        """
        session = self.get_session()
        try:
            predictions = session.query(
                PredictionRecord, EmailRecord
            ).join(
                EmailRecord, PredictionRecord.email_id == EmailRecord.id
            ).filter(
                PredictionRecord.model_name == 'ensemble'
            ).order_by(
                PredictionRecord.timestamp.desc()
            ).limit(limit).all()
            
            results = []
            for pred, email in predictions:
                results.append({
                    'id': pred.id,
                    'timestamp': pred.timestamp.isoformat(),
                    'subject': email.subject[:50] + '...' if len(email.subject) > 50 else email.subject,
                    'sender': email.sender_email,
                    'prediction': pred.prediction_label,
                    'confidence': round(pred.confidence, 3),
                    'risk_score': round(pred.risk_score, 1)
                })
            return results
        except Exception as e:
            self.logger.error(f"Error getting recent predictions: {str(e)}")
            return []
        finally:
            session.close()
    
    def get_model_performance(self):
        """
        Get model performance comparison.
        
        Returns:
            dict: Model performance data
        """
        session = self.get_session()
        try:
            models = ['random_forest', 'svm', 'ensemble']
            performance_data = {}
            
            for model in models:
                predictions = session.query(PredictionRecord).filter(
                    PredictionRecord.model_name == model
                ).all()
                if predictions:
                    avg_confidence = np.mean([p.confidence for p in predictions])
                    phishing_count = sum(1 for p in predictions if p.prediction == 1)
                    total_count = len(predictions)
                    performance_data[model] = {
                        'total_predictions': total_count,
                        'phishing_detected': phishing_count,
                        'average_confidence': round(avg_confidence, 3),
                        'phishing_rate': round((phishing_count / total_count) * 100, 2) if total_count > 0 else 0
                    }
            return performance_data
        except Exception as e:
            self.logger.error(f"Error getting model performance: {str(e)}")
            return {}
        finally:
            session.close()
    
    def cleanup_old_records(self, days=90):
        """
        Clean up old records from the database.
        
        Args:
            days (int): Number of days to keep records
        """
        session = self.get_session()
        try:
            cutoff_date = datetime.utcnow() - pd.Timedelta(days=days)
            
            # Delete old user activity records
            deleted_activity = session.query(UserActivity).filter(
                UserActivity.timestamp < cutoff_date
            ).delete()
            
            # Delete old prediction records
            deleted_predictions = session.query(PredictionRecord).filter(
                PredictionRecord.timestamp < cutoff_date
            ).delete()
            
            # Delete old email records (only if no associated predictions)
            deleted_emails = session.query(EmailRecord).filter(
                EmailRecord.timestamp < cutoff_date,
                ~EmailRecord.id.in_(
                    session.query(PredictionRecord.email_id).distinct()
                )
            ).delete(synchronize_session=False)
            
            session.commit()
            
            self.logger.info(f"Cleanup completed: {deleted_activity} activity records, "
                             f"{deleted_predictions} prediction records, "
                             f"{deleted_emails} email records deleted")
        except Exception as e:
            session.rollback()
            self.logger.error(f"Error during cleanup: {str(e)}")
            raise
        finally:
            session.close()

def get_database_manager():
    """Get database manager instance."""
    return DatabaseManager()

if __name__ == "__main__":
    # Test database operations
    try:
        db_manager = DatabaseManager()
        
        # Test email storage
        test_email = {
            'sender_email': 'test@example.com',
            'sender_name': 'Test User',
            'receiver': 'user@company.com',
            'subject': 'Test Email',
            'body': 'This is a test email',
            'processed_text': 'test email',
            'urls': ['http://example.com']
        }
        
        email_id = db_manager.store_email(test_email)
        print(f"Test email stored with ID: {email_id}")
        
        # Test statistics retrieval
        stats = db_manager.get_prediction_statistics()
        print(f"Current statistics: {stats}")
        
    except Exception as e:
        print(f"Database test failed: {str(e)}")
