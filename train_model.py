"""
Enhanced Model Training Module for AI-Powered Phishing Email Detection System
Updated to match the comprehensive training approach with balanced datasets
"""

import pandas as pd
import numpy as np
import joblib
import logging
import random
import os
import re
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import (
    train_test_split, GridSearchCV, cross_val_score, StratifiedKFold
)
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)
import matplotlib.pyplot as plt
import seaborn as sns
from config import Config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedPhishingDetectionTrainer:
    """
    Enhanced machine learning trainer for phishing email detection.
    Includes dataset creation, feature extraction, and model training.
    """
    
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.best_models = {}
        self.training_history = {}
        self.tfidf_vectorizer = None
        self.scaler = None
        self.feature_names = []
        self.logger = logging.getLogger(__name__)

    def create_comprehensive_balanced_dataset(self, samples_per_class=500):
        """Create a comprehensive balanced dataset with realistic email patterns"""
        logger.info(f"Creating balanced dataset with {samples_per_class} samples per class...")
        
        # Set random seed for reproducibility
        random.seed(self.random_state)
        np.random.seed(self.random_state)
        
        # Enhanced legitimate email templates
        legitimate_templates = [
            # Business Communications
            "Thank you for your order #{order_id}. Your items will be shipped within {days} business days.",
            "Meeting reminder: {meeting_type} at {time} {day} in {location}. Please bring your reports.",
            "Project update: The {feature} has been deployed to production. Please test and provide feedback.",
            "Your monthly bank statement is now available. You can view it by logging into your account.",
            "Your subscription to our newsletter has been confirmed. Thank you for subscribing!",
            "Reminder: Your appointment is scheduled for {day} at {time}. Please arrive 15 minutes early.",
            
            # Personal Communications
            "Hi {name}, Hope you're doing well. Just wanted to follow up on our meeting yesterday. Best regards, {sender}",
            "Happy Birthday! Wishing you a wonderful day filled with joy and celebration.",
            "Thank you for attending our webinar. The recording and slides are now available for download.",
            "Your flight booking confirmation for Flight {flight} on {date}. Have a great trip!",
            
            # System Notifications
            "Your password has been successfully updated. If this wasn't you, please contact support.",
            "System maintenance scheduled for this weekend. Services may be briefly interrupted.",
            "Your report has been generated and is ready for download in your dashboard.",
            "Training session on new software tools is scheduled for next {day}.",
            "Invoice #{invoice_id} is now available in your account dashboard.",
            
            # Work Communications  
            "Weekly team meeting scheduled for {day} at {time}. Please confirm your attendance.",
            "Performance review meeting set for next week. Please prepare your self-assessment.",
            "New employee orientation will be held on {day} morning at 9 AM.",
            "Office closure notice: We will be closed for the holiday weekend.",
            "Quarterly results presentation scheduled for next {day} afternoon.",
        ]
        
        # Enhanced phishing email templates with modern attack patterns
        phishing_templates = [
            # Account Security Scams
            "URGENT: Your {service} account will be suspended unless you verify immediately. Click: {url}",
            "Security Alert: Unusual activity detected on your {service} account. Verify here: {url}",
            "Your {service} account has been limited. Please verify your information: {url}",
            "IMPORTANT: Your account access will be revoked in {hours} hours. Restore: {url}",
            "Suspicious login detected from {location}. If this wasn't you, secure account: {url}",
            
            # Financial Scams
            "Congratulations! You have won ${amount} in our lottery. Claim your prize: {url}",
            "You have received a money transfer of ${amount}. Claim it now: {url}",
            "Your credit card will be charged ${amount} unless you cancel immediately: {url}",
            "Tax refund of ${amount} available. Claim here: {url}",
            "Your {bank} card has been blocked. Unblock here: {url}",
            
            # Service Impersonation
            "Your {service} subscription has expired. Update payment method: {url}",
            "Your {service} premium trial ending. Continue access: {url}",
            "Your {service} storage is full. Upgrade now or lose files: {url}",
            "Your {service} listing has been removed. Restore it here: {url}",
            "Your {service} channel received a strike. Appeal immediately: {url}",
            
            # Investment & Get-Rich-Quick Schemes
            "Limited time offer! Get rich quick with our guaranteed investment scheme. Invest: {url}",
            "Bitcoin investment opportunity: {percent}% returns guaranteed! Invest now: {url}",
            "Cryptocurrency wallet compromised. Secure it immediately: {url}",
            "Stock market insider tip: Make ${amount} in {days} days. Join: {url}",
            "Forex trading bot guarantees ${amount}/day profit. Download: {url}",
        ]
        
        # Generate variations for legitimate emails
        legitimate_variations = {
            '{order_id}': ['12345', '67890', '54321', '98765', '11111'],
            '{days}': ['2-3', '3-5', '1-2', '5-7'],
            '{meeting_type}': ['Team standup', 'Weekly review', 'Project sync', 'All hands'],
            '{time}': ['10 AM', '2 PM', '9 AM', '3 PM', '11 AM'],
            '{day}': ['tomorrow', 'Monday', 'Friday', 'next Tuesday'],
            '{location}': ['conference room B', 'boardroom', 'main hall', 'zoom'],
            '{feature}': ['new feature', 'security update', 'bug fix', 'enhancement'],
            '{name}': ['John', 'Sarah', 'Mike', 'Lisa', 'David'],
            '{sender}': ['Alice', 'Bob', 'Carol', 'Dan', 'Eve'],
            '{flight}': ['AA123', 'DL456', 'UA789', 'SW101'],
            '{date}': ['December 15th', 'January 10th', 'March 5th'],
            '{invoice_id}': ['INV-001', 'INV-002', 'INV-003'],
        }
        
        # Generate phishing email variations
        phishing_variations = {
            '{service}': ['PayPal', 'Amazon', 'Netflix', 'Microsoft', 'Google', 'Facebook', 'Apple'],
            '{url}': ['http://fake-paypal.com/verify', 'http://suspicious-site.com/login', 'http://192.168.1.100/secure'],
            '{hours}': ['24', '48', '72', '12'],
            '{location}': ['Russia', 'China', 'Nigeria', 'Unknown Location'],
            '{amount}': ['10000', '50000', '25000', '100000', '5000'],
            '{bank}': ['Chase', 'Bank of America', 'Wells Fargo', 'Citibank'],
            '{percent}': ['1000', '500', '300', '2000'],
            '{days}': ['7', '30', '14', '3']
        }
        
        def generate_variations(templates, variations_dict, target_count):
            emails = []
            for _ in range(target_count):
                template = random.choice(templates)
                email = template
                for placeholder, options in variations_dict.items():
                    if placeholder in email:
                        email = email.replace(placeholder, random.choice(options))
                emails.append(email)
            return emails
        
        # Generate emails
        legitimate_emails = generate_variations(legitimate_templates, legitimate_variations, samples_per_class)
        phishing_emails = generate_variations(phishing_templates, phishing_variations, samples_per_class)
        
        # Create DataFrame
        all_emails = legitimate_emails + phishing_emails
        all_labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
        
        # Create additional metadata features
        email_data = []
        for email, label in zip(all_emails, all_labels):
            email_data.append({
                'text': email,
                'label': label,
                'email_length': len(email),
                'word_count': len(email.split()),
                'url_count': email.count('http'),
                'exclamation_count': email.count('!'),
                'question_count': email.count('?'),
                'dollar_count': email.count('$'),
                'urgent_words': sum(1 for word in ['urgent', 'immediate', 'asap', 'hurry'] 
                                   if word.lower() in email.lower()),
                'suspicious_keywords': sum(1 for word in ['verify', 'click', 'suspended', 'limited', 'expires'] 
                                         if word.lower() in email.lower())
            })
        
        df = pd.DataFrame(email_data)
        df = df.sample(frac=1, random_state=self.random_state).reset_index(drop=True)  # Shuffle
        
        logger.info(f"✅ Created balanced dataset:")
        logger.info(f"   Total samples: {len(df)}")
        logger.info(f"   Legitimate: {sum(df['label'] == 0)} ({sum(df['label'] == 0)/len(df)*100:.1f}%)")
        logger.info(f"   Phishing: {sum(df['label'] == 1)} ({sum(df['label'] == 1)/len(df)*100:.1f}%)")
        
        return df

    def preprocess_text(self, text):
        """Simple but effective text preprocessing"""
        # Convert to lowercase
        text = text.lower()
        
        # Remove special characters but keep spaces
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text

    def extract_features(self, df, fit_vectorizer=True):
        """Enhanced feature extraction with TF-IDF and metadata"""
        logger.info("Extracting features...")
        
        # Preprocess text
        df['processed_text'] = df['text'].apply(self.preprocess_text)
        
        # TF-IDF Vectorization using config parameters
        if fit_vectorizer:
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=Config.MAX_FEATURES,
                stop_words='english',
                ngram_range=Config.NGRAM_RANGE,
                min_df=Config.MIN_DF,
                max_df=Config.MAX_DF,
                sublinear_tf=Config.SUBLINEAR_TF
            )
            tfidf_features = self.tfidf_vectorizer.fit_transform(df['processed_text'])
        else:
            tfidf_features = self.tfidf_vectorizer.transform(df['processed_text'])
        
        # Convert to dense array
        tfidf_dense = tfidf_features.toarray()
        
        # Create feature DataFrame
        feature_names = [f"tfidf_{i}" for i in range(tfidf_dense.shape[1])]
        feature_df = pd.DataFrame(tfidf_dense, columns=feature_names)
        
        # Add metadata features
        metadata_features = ['email_length', 'word_count', 'url_count', 'exclamation_count', 
                           'question_count', 'dollar_count', 'urgent_words', 'suspicious_keywords']
        
        for feature in metadata_features:
            if feature in df.columns:
                feature_df[feature] = df[feature].values
        
        self.feature_names = list(feature_df.columns)
        
        logger.info(f"✅ Feature extraction completed:")
        logger.info(f"   TF-IDF features: {tfidf_dense.shape[1]}")
        logger.info(f"   Metadata features: {len(metadata_features)}")
        logger.info(f"   Total features: {len(self.feature_names)}")
        
        # Only return labels if 'label' column exists
        if 'label' in df.columns:
            return feature_df, df['label']
        else:
            return feature_df, None

    def create_random_forest_model(self, **kwargs):
        """Create Random Forest model with balanced parameters"""
        default_params = {
            'n_estimators': 100,
            'max_depth': 20,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'max_features': 'sqrt',
            'class_weight': 'balanced',
            'random_state': self.random_state,
            'n_jobs': -1
        }
        default_params.update(kwargs)
        return RandomForestClassifier(**default_params)

    def create_svm_model(self, **kwargs):
        """Create SVM model with balanced parameters"""
        default_params = {
            'kernel': 'rbf',
            'C': 1.0,
            'gamma': 'scale',
            'class_weight': 'balanced',  # Key for fixing SVM bias!
            'probability': True,
            'random_state': self.random_state
        }
        default_params.update(kwargs)
        return SVC(**default_params)

    def tune_random_forest(self, X_train, y_train, cv=3):
        """Tune Random Forest hyperparameters"""
        self.logger.info("🌲 Tuning Random Forest hyperparameters...")
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'max_features': ['sqrt', 'log2']
        }
        rf = self.create_random_forest_model()
        grid_search = GridSearchCV(
            estimator=rf,
            param_grid=param_grid,
            cv=cv,
            scoring='f1',
            n_jobs=-1,
            verbose=1
        )
        grid_search.fit(X_train, y_train)
        self.logger.info(f"🎯 Best Random Forest parameters: {grid_search.best_params_}")
        self.logger.info(f"🎯 Best Random Forest F1 score: {grid_search.best_score_:.4f}")
        self.best_models['random_forest'] = grid_search.best_estimator_
        return grid_search

    def tune_svm(self, X_train, y_train, cv=3):
        """Tune SVM hyperparameters with proper scaling"""
        self.logger.info("🤖 Tuning SVM hyperparameters...")
        
        # Feature scaling (CRITICAL for SVM!)
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        param_grid = {
            'C': [0.1, 1, 10],
            'gamma': ['scale', 'auto', 0.01, 0.1],
            'kernel': ['rbf', 'linear']
        }
        
        svm = self.create_svm_model()
        grid_search = GridSearchCV(
            estimator=svm,
            param_grid=param_grid,
            cv=cv,
            scoring='f1',
            n_jobs=-1,
            verbose=1
        )
        grid_search.fit(X_train_scaled, y_train)
        self.logger.info(f"🎯 Best SVM parameters: {grid_search.best_params_}")
        self.logger.info(f"🎯 Best SVM F1 score: {grid_search.best_score_:.4f}")
        self.best_models['svm'] = grid_search.best_estimator_
        return grid_search

    def train_models(self, X_train, y_train, tune_hyperparameters=True):
        """Train both Random Forest and SVM models"""
        self.logger.info("🚀 Starting model training...")
        
        if tune_hyperparameters:
            # Tune Random Forest
            self.tune_random_forest(X_train, y_train)
            
            # Tune SVM with scaling
            self.tune_svm(X_train, y_train)
        else:
            self.logger.info("Training with default parameters...")
            # Random Forest
            rf = self.create_random_forest_model()
            rf.fit(X_train, y_train)
            self.best_models['random_forest'] = rf
            
            # SVM with scaling
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            svm = self.create_svm_model()
            svm.fit(X_train_scaled, y_train)
            self.best_models['svm'] = svm
        
        self.logger.info("✅ Model training completed!")

    def evaluate_model(self, model, X_test, y_test, model_name):
        """Evaluate a single model"""
        self.logger.info(f"📊 Evaluating {model_name}...")
        
        # Handle SVM scaling
        if model_name == 'svm' and self.scaler:
            X_test_eval = self.scaler.transform(X_test)
        else:
            X_test_eval = X_test
        
        y_pred = model.predict(X_test_eval)
        y_pred_proba = model.predict_proba(X_test_eval)[:, 1] if hasattr(model, 'predict_proba') else None
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
        }
        
        if y_pred_proba is not None:
            metrics['roc_auc'] = roc_auc_score(y_test, y_pred_proba)
        
        self.training_history[model_name] = {
            'metrics': metrics,
            'predictions': y_pred,
            'probabilities': y_pred_proba,
            'timestamp': datetime.now()
        }
        
        print(f"\n{model_name.upper()} RESULTS:")
        print("=" * 40)
        for metric, value in metrics.items():
            print(f"{metric.capitalize()}: {value:.4f}")
        
        return metrics

    def evaluate_all_models(self, X_test, y_test):
        """Evaluate all trained models"""
        results = {}
        for model_name, model in self.best_models.items():
            metrics = self.evaluate_model(model, X_test, y_test, model_name)
            results[model_name] = metrics
        self.compare_models(results)
        return results

    def compare_models(self, results):
        """Compare model performance"""
        print("\n📈 MODEL COMPARISON:")
        print("=" * 50)
        comparison_df = pd.DataFrame(results).T
        comparison_df = comparison_df.round(4)
        print(comparison_df)
        
        print("\n🏆 Best models by metric:")
        for metric in comparison_df.columns:
            best_model = comparison_df[metric].idxmax()
            best_score = comparison_df[metric].max()
            print(f"{metric.capitalize()}: {best_model} ({best_score:.4f})")

    def create_visualizations(self, X_test, y_test):
        """Create comprehensive visualizations"""
        logger.info("📊 Creating visualizations...")
        
        # 1. Confusion Matrices
        n_models = len(self.best_models)
        fig, axes = plt.subplots(1, n_models, figsize=(5 * n_models, 4))
        if n_models == 1:
            axes = [axes]
        
        for idx, (model_name, model) in enumerate(self.best_models.items()):
            # Handle SVM scaling
            if model_name == 'svm' and self.scaler:
                X_test_viz = self.scaler.transform(X_test)
            else:
                X_test_viz = X_test
                
            y_pred = model.predict(X_test_viz)
            cm = confusion_matrix(y_test, y_pred)
            
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[idx])
            axes[idx].set_title(f'{model_name.replace("_", " ").title()}\nF1: {f1_score(y_test, y_pred):.3f}')
            axes[idx].set_xlabel('Predicted')
            axes[idx].set_ylabel('Actual')
            axes[idx].set_xticklabels(['Legitimate', 'Phishing'])
            axes[idx].set_yticklabels(['Legitimate', 'Phishing'])
        
        plt.tight_layout()
        os.makedirs('plots', exist_ok=True)
        plt.savefig('plots/confusion_matrices.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Feature Importance (Random Forest)
        if 'random_forest' in self.best_models:
            self.plot_feature_importance(self.feature_names)

    def plot_feature_importance(self, feature_names, top_n=20):
        """Plot Random Forest feature importance"""
        if 'random_forest' not in self.best_models:
            self.logger.warning("Random Forest model not available for feature importance plot")
            return
        
        rf_model = self.best_models['random_forest']
        if hasattr(rf_model, 'feature_importances_'):
            importances = rf_model.feature_importances_
            indices = np.argsort(importances)[::-1]
            n_feats = len(importances)
            top_n = min(top_n, n_feats)
            indices = indices[:top_n]
            
            labels = [feature_names[i] if i < len(feature_names) else f'Feature_{i}' for i in indices]
            
            plt.figure(figsize=(12, 8))
            plt.title(f'Top {top_n} Feature Importances (Random Forest)')
            plt.barh(range(top_n), importances[indices])
            plt.yticks(range(top_n), labels)
            plt.xlabel('Importance')
            plt.gca().invert_yaxis()
            plt.tight_layout()
            plt.savefig('plots/feature_importance.png', dpi=300, bbox_inches='tight')
            plt.close()

    def save_models(self, model_dir=None):
        """Save all trained models and components"""
        model_dir = model_dir or Config.MODEL_DIR
        os.makedirs(model_dir, exist_ok=True)
        
        logger.info("💾 Saving models...")
        
        # Save models using config paths
        if 'random_forest' in self.best_models:
            joblib.dump(self.best_models['random_forest'], Config.RANDOM_FOREST_MODEL_PATH)
            logger.info(f"✅ Saved Random Forest to {Config.RANDOM_FOREST_MODEL_PATH}")
        
        if 'svm' in self.best_models:
            joblib.dump(self.best_models['svm'], Config.SVM_MODEL_PATH)
            logger.info(f"✅ Saved SVM to {Config.SVM_MODEL_PATH}")
        
        if self.scaler:
            joblib.dump(self.scaler, Config.SVM_SCALER_PATH)
            logger.info(f"✅ Saved SVM Scaler to {Config.SVM_SCALER_PATH}")
        
        if self.tfidf_vectorizer:
            joblib.dump(self.tfidf_vectorizer, Config.TFIDF_VECTORIZER_PATH)
            logger.info(f"✅ Saved TF-IDF Vectorizer to {Config.TFIDF_VECTORIZER_PATH}")
        
        # Save feature names
        if hasattr(Config, 'FEATURE_NAMES_PATH'):
            feature_path = Config.FEATURE_NAMES_PATH
        else:
            feature_path = os.path.join(model_dir, 'feature_names.txt')
        
        with open(feature_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.feature_names))
        logger.info(f"✅ Saved feature names to {feature_path}")

    def cross_validate_models(self, X_train, y_train, cv=5):
        """Perform cross-validation on trained models"""
        self.logger.info("🔄 Performing cross-validation...")
        cv_results = {}
        
        for model_name, model in self.best_models.items():
            # Handle SVM scaling for cross-validation
            if model_name == 'svm' and self.scaler:
                X_cv = self.scaler.fit_transform(X_train)
            else:
                X_cv = X_train
                
            scores = cross_val_score(model, X_cv, y_train, cv=cv, scoring='f1')
            cv_results[model_name] = {
                'mean_f1': scores.mean(),
                'std_f1': scores.std(),
                'scores': scores
            }
            print(f"\n{model_name.upper()} Cross-Validation Results:")
            print(f"F1 Score: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
        
        return cv_results

def train_enhanced_phishing_detection_models(samples_per_class=500, tune_hyperparameters=True, save_models=True):
    """
    Main function to train enhanced phishing detection models
    """
    print("🚀 Enhanced AI-Powered Phishing Email Detection System - Training")
    print("=" * 80)
    
    trainer = EnhancedPhishingDetectionTrainer()
    
    try:
        # Step 1: Create balanced dataset
        logger.info("Step 1: Creating balanced dataset...")
        df = trainer.create_comprehensive_balanced_dataset(samples_per_class=samples_per_class)
        
        # Step 2: Feature extraction
        logger.info("Step 2: Feature extraction...")
        X, y = trainer.extract_features(df)
        
        # Step 3: Train-test split
        logger.info("Step 3: Splitting data...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training samples: {X_train.shape[0]}")
        logger.info(f"Test samples: {X_test.shape[0]}")
        logger.info(f"Features: {X_train.shape[1]}")
        
        # Step 4: Train models
        trainer.train_models(X_train, y_train, tune_hyperparameters=tune_hyperparameters)
        
        # Step 5: Evaluate models
        trainer.evaluate_all_models(X_test, y_test)
        
        # Step 6: Cross-validation
        trainer.cross_validate_models(X_train, y_train)
        
        # Step 7: Create visualizations
        trainer.create_visualizations(X_test, y_test)
        
        # Step 8: Save models
        if save_models:
            trainer.save_models()
        
        print("\n" + "=" * 80)
        print("🎉 TRAINING COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("✅ Models are ready for deployment!")
        
        return trainer

    except Exception as e:
        logger.error(f"❌ Training failed: {e}")
        raise

if __name__ == "__main__":
    # Train the enhanced models
    trainer = train_enhanced_phishing_detection_models(
        samples_per_class=500,
        tune_hyperparameters=True,
        save_models=True
    )
    print("\n🎯 Training completed successfully! Models are ready for use.")
