"""
Real-Time Accuracy Tracker for Phishing Email Detection System
Tracks accuracy, performance metrics, and user feedback in real-time
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
from dataclasses import dataclass
import threading

@dataclass
class PredictionRecord:
    """Data class for storing prediction records"""
    timestamp: str
    prediction: int
    confidence: float
    actual_label: Optional[int] = None
    user_feedback: Optional[str] = None
    email_hash: Optional[str] = None
    correct: Optional[bool] = None

class RealTimeAccuracyTracker:
    """Real-time accuracy tracker with persistence"""
    
    def __init__(self, db_path='data/accuracy_tracker.db'):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # In-memory cache for fast access
        self._cache = {
            'total_predictions': 0,
            'correct_predictions': 0,
            'accuracy': 0.0,
            'last_updated': datetime.now().isoformat()
        }
        
        # Load initial stats
        self._update_cache()
    
    def _init_database(self):
        """Initialize SQLite database for storing predictions"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    prediction INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    actual_label INTEGER,
                    user_feedback TEXT,
                    email_hash TEXT,
                    correct INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON predictions(timestamp);
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_actual_label ON predictions(actual_label);
            """)
    
    def add_prediction(self, prediction: int, confidence: float, 
                      actual_label: Optional[int] = None, 
                      user_feedback: Optional[str] = None,
                      email_hash: Optional[str] = None) -> None:
        """Add a new prediction record"""
        
        with self.lock:
            timestamp = datetime.now().isoformat()
            correct = None
            
            if actual_label is not None:
                correct = 1 if prediction == actual_label else 0
            
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO predictions 
                    (timestamp, prediction, confidence, actual_label, user_feedback, email_hash, correct)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, prediction, confidence, actual_label, user_feedback, email_hash, correct))
            
            # Update cache
            self._update_cache()
            
            self.logger.info(f"Added prediction: {prediction} (confidence: {confidence:.3f})")
    
    def add_user_feedback(self, email_hash: str, actual_label: int, 
                         feedback: str = "user_correction") -> bool:
        """Add user feedback to correct a prediction"""
        
        with self.lock:
            # Update the most recent prediction with this email hash
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, prediction FROM predictions 
                    WHERE email_hash = ? 
                    ORDER BY created_at DESC LIMIT 1
                """, (email_hash,))
                
                result = cursor.fetchone()
                if result:
                    record_id, prediction = result
                    correct = 1 if prediction == actual_label else 0
                    
                    conn.execute("""
                        UPDATE predictions 
                        SET actual_label = ?, user_feedback = ?, correct = ?
                        WHERE id = ?
                    """, (actual_label, feedback, correct, record_id))
                    
                    self._update_cache()
                    self.logger.info(f"Updated prediction {record_id} with user feedback")
                    return True
        
        return False
    
    def _update_cache(self):
        """Update in-memory cache with latest statistics"""
        with sqlite3.connect(self.db_path) as conn:
            # Total predictions
            cursor = conn.execute("SELECT COUNT(*) FROM predictions")
            total = cursor.fetchone()[0]
            
            # Predictions with known actual labels
            cursor = conn.execute("SELECT COUNT(*) FROM predictions WHERE actual_label IS NOT NULL")
            labeled_total = cursor.fetchone()[0]
            
            # Correct predictions
            cursor = conn.execute("SELECT COUNT(*) FROM predictions WHERE correct = 1")
            correct = cursor.fetchone()[0]
            
            # Calculate accuracy
            accuracy = (correct / labeled_total) if labeled_total > 0 else 0.0
            
            self._cache.update({
                'total_predictions': total,
                'labeled_predictions': labeled_total,
                'correct_predictions': correct,
                'accuracy': accuracy,
                'last_updated': datetime.now().isoformat()
            })
    
    def get_real_time_stats(self, hours: int = 24) -> Dict:
        """Get real-time accuracy statistics"""
        
        cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            # Recent predictions
            cursor = conn.execute("""
                SELECT COUNT(*) FROM predictions 
                WHERE timestamp >= ?
            """, (cutoff_time,))
            recent_total = cursor.fetchone()[0]
            
            # Recent labeled predictions
            cursor = conn.execute("""
                SELECT COUNT(*) FROM predictions 
                WHERE timestamp >= ? AND actual_label IS NOT NULL
            """, (cutoff_time,))
            recent_labeled = cursor.fetchone()[0]
            
            # Recent correct predictions
            cursor = conn.execute("""
                SELECT COUNT(*) FROM predictions 
                WHERE timestamp >= ? AND correct = 1
            """, (cutoff_time,))
            recent_correct = cursor.fetchone()[0]
            
            # Recent accuracy
            recent_accuracy = (recent_correct / recent_labeled) if recent_labeled > 0 else 0.0
            
            # Model performance breakdown
            cursor = conn.execute("""
                SELECT prediction, COUNT(*) as count, AVG(confidence) as avg_confidence
                FROM predictions 
                WHERE timestamp >= ?
                GROUP BY prediction
            """, (cutoff_time,))
            
            model_breakdown = {}
            for row in cursor.fetchall():
                label = "Phishing" if row[0] == 1 else "Legitimate"
                model_breakdown[label] = {
                    'count': row[1],
                    'avg_confidence': round(row[2], 3) if row[2] else 0
                }
            
            # Confidence distribution
            cursor = conn.execute("""
                SELECT 
                    COUNT(CASE WHEN confidence >= 0.9 THEN 1 END) as high_conf,
                    COUNT(CASE WHEN confidence >= 0.7 AND confidence < 0.9 THEN 1 END) as med_conf,
                    COUNT(CASE WHEN confidence < 0.7 THEN 1 END) as low_conf
                FROM predictions 
                WHERE timestamp >= ?
            """, (cutoff_time,))
            
            conf_dist = cursor.fetchone()
            
        return {
            # Overall stats
            'overall_accuracy': round(self._cache['accuracy'] * 100, 2),
            'total_predictions': self._cache['total_predictions'],
            'labeled_predictions': self._cache['labeled_predictions'],
            'correct_predictions': self._cache['correct_predictions'],
            
            # Recent stats (last 24 hours by default)
            'recent_accuracy': round(recent_accuracy * 100, 2),
            'recent_total': recent_total,
            'recent_labeled': recent_labeled,
            'recent_correct': recent_correct,
            
            # Model performance
            'model_breakdown': model_breakdown,
            
            # Confidence distribution
            'confidence_distribution': {
                'high_confidence': conf_dist[0] or 0,      # >= 90%
                'medium_confidence': conf_dist[1] or 0,    # 70-90%
                'low_confidence': conf_dist[2] or 0        # < 70%
            },
            
            # Meta info
            'last_updated': self._cache['last_updated'],
            'time_window_hours': hours
        }
    
    def get_accuracy_trend(self, days: int = 7) -> List[Dict]:
        """Get accuracy trend over time"""
        
        trends = []
        
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            start_date = date.strftime('%Y-%m-%d 00:00:00')
            end_date = date.strftime('%Y-%m-%d 23:59:59')
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) as total, 
                           SUM(correct) as correct,
                           AVG(confidence) as avg_confidence
                    FROM predictions 
                    WHERE timestamp BETWEEN ? AND ? 
                    AND actual_label IS NOT NULL
                """, (start_date, end_date))
                
                result = cursor.fetchone()
                total, correct, avg_conf = result
                
                accuracy = (correct / total * 100) if total > 0 else 0
                
                trends.append({
                    'date': date.strftime('%Y-%m-%d'),
                    'accuracy': round(accuracy, 2),
                    'total_predictions': total or 0,
                    'correct_predictions': correct or 0,
                    'avg_confidence': round(avg_conf, 3) if avg_conf else 0
                })
        
        return list(reversed(trends))  # Most recent first

# Global instance
accuracy_tracker = RealTimeAccuracyTracker()
