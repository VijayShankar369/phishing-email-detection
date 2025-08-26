"""
Main training script for the AI-Powered Phishing Email Detection System.
This script demonstrates the complete workflow from data loading to model training and evaluation.
"""

import pandas as pd
import numpy as np
import os
import logging
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Import our custom modules
from src.data_preprocessing import EmailPreprocessor, load_and_preprocess_data
from src.feature_extraction import FeatureExtractor, create_feature_pipeline
from src.model_training import PhishingDetectionTrainer, train_phishing_detection_models
from config import Config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_dataset():
    """
    Create a sample dataset for demonstration purposes.
    In a real implementation, you would load actual phishing and legitimate email datasets.
    """
    logger.info("Creating sample dataset...")
    
    # Sample phishing emails
    phishing_emails = [
        "URGENT: Your account will be suspended unless you verify your information immediately. Click here: http://fake-bank.com/verify",
        "Congratulations! You have won $10,000 in our lottery. Claim your prize now by clicking here: http://fake-lottery.com",
        "Your PayPal account has been limited. Please verify your account by clicking here: http://fake-paypal.com/verify",
        "Security Alert: Unusual activity detected on your account. Verify your identity immediately: http://suspicious-site.com",
        "Limited time offer! Get rich quick with our guaranteed investment scheme. Act now!",
        "IMPORTANT: Your credit card will be charged $500 unless you cancel immediately. Click here: http://scam-site.com",
        "You have received a money transfer of $50,000. Claim it now: http://fake-transfer.com",
        "Your Amazon account has been suspended. Restore access here: http://fake-amazon.com",
        "IRS Notice: You owe back taxes. Pay immediately to avoid penalties: http://fake-irs.com",
        "Your package is held at customs. Pay fees to release: http://fake-shipping.com"
    ]
    
    # Sample legitimate emails
    legitimate_emails = [
        "Hi John, Hope you're doing well. Just wanted to follow up on our meeting yesterday. Best regards, Sarah",
        "Meeting reminder: Team standup at 10 AM tomorrow in conference room B. Please bring your progress reports.",
        "Thank you for your order #12345. Your items will be shipped within 2-3 business days.",
        "Your monthly bank statement is now available. You can view it by logging into your account.",
        "Happy Birthday! Wishing you a wonderful day filled with joy and celebration.",
        "Project update: The new feature has been deployed to production. Please test and provide feedback.",
        "Your subscription to our newsletter has been confirmed. Thank you for subscribing!",
        "Reminder: Your appointment is scheduled for tomorrow at 2 PM. Please arrive 15 minutes early.",
        "Thank you for attending our webinar. The recording and slides are now available for download.",
        "Your flight booking confirmation for Flight AA123 on December 15th. Have a great trip!"
    ]
    
    # Create extended dataset with variations
    extended_phishing = []
    extended_legitimate = []
    
    # Add variations and more samples
    for _ in range(50):  # Create 500 phishing samples
        extended_phishing.extend(phishing_emails)
    
    for _ in range(50):  # Create 500 legitimate samples
        extended_legitimate.extend(legitimate_emails)
    
    # Create DataFrame
    all_emails = extended_phishing + extended_legitimate
    all_labels = [1] * len(extended_phishing) + [0] * len(extended_legitimate)
    
    df = pd.DataFrame({
        'text': all_emails,
        'label': all_labels
    })
    
    # Shuffle the dataset
    df = df.sample(frac=1).reset_index(drop=True)
    
    logger.info(f"Created dataset with {len(df)} samples")
    logger.info(f"Phishing emails: {sum(df['label'])}")
    logger.info(f"Legitimate emails: {len(df) - sum(df['label'])}")
    
    return df

def download_real_dataset():
    """
    Download and prepare a real phishing dataset.
    This function would typically download from sources like:
    - Kaggle phishing datasets
    - UCI Machine Learning Repository
    - Research paper datasets
    """
    logger.info("For this demo, we'll use the sample dataset.")
    logger.info("In production, you would download real datasets from:")
    logger.info("- Kaggle: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset")
    logger.info("- UCI: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset")
    logger.info("- Research papers and public repositories")
    return None

def create_training_report(trainer, results, X_train, y_train, X_test, y_test):
    """Create a comprehensive training report."""
    logger.info("Creating training report...")
    
    report_content = []
    report_content.append("# AI-Powered Phishing Email Detection System - Training Report")
    report_content.append("=" * 60)
    report_content.append("")
    
    # Dataset information
    report_content.append("## Dataset Information")
    report_content.append(f"- Training samples: {X_train.shape[0]}")
    report_content.append(f"- Test samples: {X_test.shape[0]}")
    report_content.append(f"- Total features: {X_train.shape[1]}")
    report_content.append(f"- Phishing samples in training: {sum(y_train)}")
    report_content.append(f"- Legitimate samples in training: {len(y_train) - sum(y_train)}")
    report_content.append("")
    
    # Model performance
    report_content.append("## Model Performance")
    for model_name, metrics in results.items():
        report_content.append(f"### {model_name.replace('_', ' ').title()}")
        report_content.append(f"- Accuracy: {metrics['accuracy']:.4f}")
        report_content.append(f"- Precision: {metrics['precision']:.4f}")
        report_content.append(f"- Recall: {metrics['recall']:.4f}")
        report_content.append(f"- F1-Score: {metrics['f1_score']:.4f}")
        if 'roc_auc' in metrics:
            report_content.append(f"- ROC AUC: {metrics['roc_auc']:.4f}")
        report_content.append("")
    
    # Best model recommendation
    best_model = max(results.items(), key=lambda x: x[1]['f1_score'])
    report_content.append("## Recommendation")
    report_content.append(f"Best performing model: **{best_model[0].replace('_', ' ').title()}**")
    report_content.append(f"F1-Score: {best_model[1]['f1_score']:.4f}")
    report_content.append("")
    
    # Feature importance (if available)
    if 'random_forest' in trainer.best_models:
        rf_model = trainer.best_models['random_forest']
        if hasattr(rf_model, 'feature_importances_'):
            top_features = np.argsort(rf_model.feature_importances_)[-10:]
            report_content.append("## Top 10 Important Features (Random Forest)")
            for i, feature_idx in enumerate(reversed(top_features)):
                importance = rf_model.feature_importances_[feature_idx]
                report_content.append(f"{i+1}. Feature {feature_idx}: {importance:.4f}")
            report_content.append("")
    
    # Technical details
    report_content.append("## Technical Details")
    report_content.append("### Preprocessing")
    report_content.append("- Text cleaning and normalization")
    report_content.append("- Tokenization and stopword removal")
    report_content.append("- Stemming/Lemmatization")
    report_content.append("")
    
    report_content.append("### Feature Extraction")
    report_content.append("- TF-IDF vectorization")
    report_content.append("- Email metadata features")
    report_content.append("- URL analysis")
    report_content.append("- Suspicious keyword detection")
    report_content.append("")
    
    report_content.append("### Machine Learning Models")
    report_content.append("- Random Forest Classifier")
    report_content.append("- Support Vector Machine (SVM)")
    report_content.append("- Ensemble prediction (majority voting)")
    report_content.append("")
    
    # Save report
    with open('training_report.md', 'w') as f:
        f.write('\n'.join(report_content))
    
    logger.info("Training report saved to training_report.md")

def main():
    """Main training pipeline."""
    logger.info("Starting AI-Powered Phishing Email Detection System Training")
    logger.info("=" * 60)
    
    # Create necessary directories
    os.makedirs('data/raw', exist_ok=True)
    os.makedirs('data/processed', exist_ok=True)
    os.makedirs('data/models', exist_ok=True)
    os.makedirs('plots', exist_ok=True)
    
    try:
        # Step 1: Load or create dataset
        logger.info("Step 1: Loading dataset...")
        real_dataset = download_real_dataset()
        if real_dataset is not None:
            df = real_dataset
        else:
            df = create_sample_dataset()
        
        # Save raw dataset
        df.to_csv('data/raw/phishing_dataset.csv', index=False)
        logger.info("Dataset saved to data/raw/phishing_dataset.csv")
        
        # Step 2: Data preprocessing
        logger.info("Step 2: Preprocessing data...")
        preprocessor = EmailPreprocessor()
        processed_df = preprocessor.preprocess_email_dataset(df)
        
        # Save processed dataset
        processed_df.to_csv('data/processed/processed_phishing_dataset.csv', index=False)
        logger.info("Processed dataset saved to data/processed/processed_phishing_dataset.csv")
        
        # Step 3: Feature extraction
        logger.info("Step 3: Extracting features...")
        X_train, X_test, y_train, y_test, feature_extractor = create_feature_pipeline(
            processed_df, target_column='label', test_size=0.2, random_state=42
        )
        
        logger.info(f"Training set size: {X_train.shape}")
        logger.info(f"Test set size: {X_test.shape}")
        
        # Save feature extractor
        feature_extractor.save_vectorizer(Config.VECTORIZER_PATH)
        
        # Step 4: Model training
        logger.info("Step 4: Training models...")
        trainer = train_phishing_detection_models(
            X_train, X_test, y_train, y_test, 
            feature_names=feature_extractor.feature_names,
            save_models=True
        )
        
        # Step 5: Model evaluation and reporting
        logger.info("Step 5: Generating final report...")
        results = trainer.evaluate_all_models(X_test, y_test)
        create_training_report(trainer, results, X_train, y_train, X_test, y_test)
        
        logger.info("Training completed successfully!")
        logger.info("=" * 60)
        logger.info("Next steps:")
        logger.info("1. Run the Flask application: python app.py")
        logger.info("2. Access the web interface at http://localhost:5000")
        logger.info("3. Test with sample emails or upload email files")
        
    except Exception as e:
        logger.error(f"Training failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()
