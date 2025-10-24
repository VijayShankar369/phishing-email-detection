"""
Accuracy Testing Script for Phishing Email Detection System
Tests model performance on custom dataset
"""

import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from src.prediction import PhishingPredictor
from config import Config
import os

def load_test_dataset():
    """Create or load test dataset"""
    # Sample test emails (you can expand this)
    test_data = [
        # Phishing emails (label = 1)
        {"text": "URGENT: Your PayPal account will be suspended unless you verify immediately. Click here: http://fake-paypal.com/verify", "label": 1},
        {"text": "Congratulations! You have won $50,000 in our lottery. Claim your prize now: http://fake-lottery.com/claim", "label": 1},
        {"text": "Security Alert: Unusual activity detected on your Amazon account. Verify here: http://suspicious-amazon.com/login", "label": 1},
        {"text": "Your credit card will be charged $299 unless you cancel immediately: http://fake-subscription.com/cancel", "label": 1},
        {"text": "IRS Notice: You owe back taxes. Pay immediately to avoid penalties: http://fake-irs.gov/pay", "label": 1},
        
        # Legitimate emails (label = 0)
        {"text": "Thank you for your order #12345. Your items will be shipped within 2-3 business days.", "label": 0},
        {"text": "Meeting reminder: Team standup at 10 AM tomorrow in conference room B. Please bring your reports.", "label": 0},
        {"text": "Your monthly bank statement is now available. You can view it by logging into your account.", "label": 0},
        {"text": "Hi John, Hope you're doing well. Just wanted to follow up on our meeting yesterday. Best regards, Sarah", "label": 0},
        {"text": "System maintenance scheduled for this weekend. Services may be briefly interrupted.", "label": 0},
    ]
    
    return pd.DataFrame(test_data)

def test_model_accuracy():
    """Test model accuracy on sample dataset"""
    print("🎯 Testing Phishing Detection Model Accuracy")
    print("=" * 50)
    
    # Load test dataset
    df_test = load_test_dataset()
    print(f"📊 Test dataset size: {len(df_test)} emails")
    print(f"   - Phishing emails: {sum(df_test['label'] == 1)}")
    print(f"   - Legitimate emails: {sum(df_test['label'] == 0)}")
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor(model_dir=Config.MODEL_DIR)
        print("✅ Models loaded successfully")
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        return
    
    # Make predictions
    predictions = []
    true_labels = df_test['label'].tolist()
    
    print("\n🔍 Testing individual emails:")
    print("-" * 50)
    
    for idx, row in df_test.iterrows():
        try:
            result = predictor.predict_single_email(row['text'])
            prediction = result['ensemble_prediction']['prediction']
            confidence = result['ensemble_prediction']['confidence']
            
            predictions.append(prediction)
            
            # Show individual results
            status = "✅" if prediction == row['label'] else "❌"
            label_text = "Phishing" if prediction == 1 else "Legitimate"
            expected_text = "Phishing" if row['label'] == 1 else "Legitimate"
            
            print(f"{status} Email {idx+1}: {label_text} (confidence: {confidence:.3f}) | Expected: {expected_text}")
            print(f"   Preview: {row['text'][:60]}...")
            print()
            
        except Exception as e:
            print(f"❌ Error predicting email {idx+1}: {e}")
            predictions.append(0)  # Default to legitimate
    
    # Calculate metrics
    accuracy = accuracy_score(true_labels, predictions)
    precision = precision_score(true_labels, predictions)
    recall = recall_score(true_labels, predictions)
    f1 = f1_score(true_labels, predictions)
    
    # Display results
    print("🏆 ACCURACY RESULTS:")
    print("=" * 50)
    print(f"Overall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall: {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score: {f1:.4f} ({f1*100:.2f}%)")
    print(f"Correct Predictions: {sum(p == t for p, t in zip(predictions, true_labels))}/{len(true_labels)}")
    
    # Detailed classification report
    print("\n📋 DETAILED CLASSIFICATION REPORT:")
    print("-" * 50)
    print(classification_report(true_labels, predictions, target_names=['Legitimate', 'Phishing']))
    
    return accuracy, precision, recall, f1

if __name__ == "__main__":
    accuracy, precision, recall, f1 = test_model_accuracy()
    
    print("\n" + "="*50)
    print("🎉 ACCURACY TEST COMPLETED!")
    print(f"🎯 Your model achieved {accuracy*100:.2f}% accuracy!")
    print("="*50)
