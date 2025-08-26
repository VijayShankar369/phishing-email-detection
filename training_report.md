# AI-Powered Phishing Email Detection System - Training Report
============================================================

## Dataset Information
- Training samples: 800
- Test samples: 200
- Total features: 250
- Phishing samples in training: 400
- Legitimate samples in training: 400

## Model Performance
### Random Forest
- Accuracy: 1.0000
- Precision: 1.0000
- Recall: 1.0000
- F1-Score: 1.0000
- ROC AUC: 1.0000

### Svm
- Accuracy: 1.0000
- Precision: 1.0000
- Recall: 1.0000
- F1-Score: 1.0000
- ROC AUC: 1.0000

## Recommendation
Best performing model: **Random Forest**
F1-Score: 1.0000

## Top 10 Important Features (Random Forest)
1. Feature 242: 0.1660
2. Feature 245: 0.0621
3. Feature 240: 0.0528
4. Feature 89: 0.0527
5. Feature 224: 0.0395
6. Feature 246: 0.0387
7. Feature 45: 0.0339
8. Feature 249: 0.0323
9. Feature 203: 0.0314
10. Feature 241: 0.0314

## Technical Details
### Preprocessing
- Text cleaning and normalization
- Tokenization and stopword removal
- Stemming/Lemmatization

### Feature Extraction
- TF-IDF vectorization
- Email metadata features
- URL analysis
- Suspicious keyword detection

### Machine Learning Models
- Random Forest Classifier
- Support Vector Machine (SVM)
- Ensemble prediction (majority voting)
