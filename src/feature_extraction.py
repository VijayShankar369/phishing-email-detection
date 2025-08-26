"""
Feature extraction module for phishing email detection.
Implements TF-IDF vectorization and additional feature engineering.
"""

import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
import joblib
import logging
from config import Config


class FeatureExtractor:
    """
    Feature extraction class for email text and metadata.
    """
    
    def __init__(self, max_features=5000, min_df=2, max_df=0.95, ngram_range=(1, 2)):
        """
        Initialize the feature extractor.
        
        Args:
            max_features (int): Maximum number of features for TF-IDF
            min_df (int): Minimum document frequency
            max_df (float): Maximum document frequency
            ngram_range (tuple): N-gram range for TF-IDF
        """
        self.max_features = max_features
        self.min_df = min_df
        self.max_df = max_df
        self.ngram_range = ngram_range
        
        self.tfidf_vectorizer = None
        self.feature_selector = None
        self.feature_names = []
        self.logger = logging.getLogger(__name__)
        
    def create_tfidf_features(self, texts, fit=True):
        """
        Create TF-IDF features from text data.
        
        Args:
            texts (list): List of preprocessed text documents
            fit (bool): Whether to fit the vectorizer
            
        Returns:
            scipy.sparse.matrix: TF-IDF feature matrix
        """
        if fit:
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=self.max_features,
                min_df=self.min_df,
                max_df=self.max_df,
                ngram_range=self.ngram_range,
                stop_words='english',
                lowercase=True,
                strip_accents='unicode'
            )
            tfidf_matrix = self.tfidf_vectorizer.fit_transform(texts)
            self.feature_names = self.tfidf_vectorizer.get_feature_names_out()
        else:
            if self.tfidf_vectorizer is None:
                raise ValueError("TF-IDF vectorizer not fitted. Call with fit=True first.")
            tfidf_matrix = self.tfidf_vectorizer.transform(texts)
            
        return tfidf_matrix
    
    def extract_email_metadata_features(self, df):
        """
        Extract metadata features from email dataset.
        
        Args:
            df (pd.DataFrame): Email dataset
            
        Returns:
            pd.DataFrame: Metadata features
        """
        features_df = pd.DataFrame()
        
        # Text length features
        if 'processed_text' in df.columns:
            features_df['text_length'] = df['processed_text'].str.len()
            features_df['word_count'] = df['processed_text'].str.split().str.len()
        elif 'text' in df.columns:
            features_df['text_length'] = df['text'].str.len()
            features_df['word_count'] = df['text'].str.split().str.len()
        
        # Subject line features if available
        if 'subject' in df.columns:
            features_df['subject_length'] = df['subject'].fillna('').str.len()
            features_df['subject_exclamation_count'] = df['subject'].fillna('').str.count('!')
            features_df['subject_question_count'] = df['subject'].fillna('').str.count(r'\?')
            features_df['subject_caps_ratio'] = df['subject'].fillna('').apply(
                lambda x: sum(1 for c in x if c.isupper()) / (len(x) + 1)
            )
        
        # URL features
        text_column = 'text' if 'text' in df.columns else 'processed_text'
        if text_column in df.columns:
            features_df['url_count'] = df[text_column].apply(self.count_urls)
            features_df['has_ip_url'] = df[text_column].apply(self.has_ip_address)
            features_df['has_shortened_url'] = df[text_column].apply(self.has_shortened_url)
        
        # Sender features if available
        if 'sender' in df.columns:
            features_df['sender_suspicious'] = df['sender'].fillna('').apply(
                self.is_suspicious_sender
            )
        
        # Suspicious keywords
        if text_column in df.columns:
            features_df['suspicious_keyword_count'] = df[text_column].apply(
                self.count_suspicious_keywords
            )
            features_df['urgency_indicators'] = df[text_column].apply(
                self.count_urgency_indicators
            )
        
        # Punctuation features
        if text_column in df.columns:
            features_df['exclamation_count'] = df[text_column].str.count('!')
            features_df['question_count'] = df[text_column].str.count(r'\?')
            features_df['caps_ratio'] = df[text_column].apply(
                lambda x: sum(1 for c in str(x) if c.isupper()) / (len(str(x)) + 1)
            )
        
        return features_df
    
    def count_urls(self, text):
        """Count URLs in text."""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$\-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return len(re.findall(url_pattern, str(text)))
    
    def has_ip_address(self, text):
        """Check if text contains IP address."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, str(text)))
    
    def has_shortened_url(self, text):
        """Check if text contains shortened URLs."""
        shortened_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        return any(domain in str(text).lower() for domain in shortened_domains)
    
    def is_suspicious_sender(self, sender):
        """Check if sender appears suspicious."""
        suspicious_patterns = [
            r'noreply@',
            r'donotreply@',
            r'[0-9]+@',
            r'@[0-9]+\.',
            r'[a-z]+[0-9]+@'
        ]
        return any(re.search(pattern, str(sender).lower()) for pattern in suspicious_patterns)
    
    def count_suspicious_keywords(self, text):
        """Count suspicious keywords in text."""
        suspicious_keywords = Config.SUSPICIOUS_KEYWORDS
        text_lower = str(text).lower()
        return sum(1 for keyword in suspicious_keywords if keyword in text_lower)
    
    def count_urgency_indicators(self, text):
        """Count urgency indicators in text."""
        urgency_words = [
            'urgent', 'immediate', 'asap', 'hurry', 'quickly', 'deadline',
            'expires', 'limited time', 'act now', 'don\'t delay'
        ]
        text_lower = str(text).lower()
        return sum(1 for word in urgency_words if word in text_lower)
    
    def select_best_features(self, X, y, k=1000):
        """
        Select best features using chi-squared test.
        
        Args:
            X (array): Feature matrix
            y (array): Target labels
            k (int): Number of features to select
            
        Returns:
            array: Selected features
        """
        self.feature_selector = SelectKBest(score_func=chi2, k=k)
        X_selected = self.feature_selector.fit_transform(X, y)
        
        # Get selected feature names
        if hasattr(self.feature_selector, 'get_support'):
            mask = self.feature_selector.get_support()
            self.selected_feature_names = [name for name, selected in 
                                          zip(self.feature_names, mask) if selected]
        
        return X_selected
    
    def combine_features(self, tfidf_features, metadata_features):
        """
        Combine TF-IDF and metadata features.
        
        Args:
            tfidf_features (scipy.sparse.matrix): TF-IDF features
            metadata_features (pd.DataFrame): Metadata features
            
        Returns:
            scipy.sparse.matrix: Combined features
        """
        from scipy import sparse
        
        # Convert metadata to numeric type to avoid object dtype error
        metadata_numeric = metadata_features.apply(pd.to_numeric, errors='coerce').fillna(0).astype(float)
        
        metadata_sparse = sparse.csr_matrix(metadata_numeric.values)
        
        combined_features = sparse.hstack([tfidf_features, metadata_sparse])
        
        return combined_features
    
    def save_vectorizer(self, filepath):
        """Save the TF-IDF vectorizer to disk."""
        if self.tfidf_vectorizer is not None:
            joblib.dump(self.tfidf_vectorizer, filepath)
            self.logger.info(f"TF-IDF vectorizer saved to {filepath}")
        else:
            self.logger.error("No vectorizer to save. Fit the vectorizer first.")
    
    def load_vectorizer(self, filepath):
        """Load the TF-IDF vectorizer from disk."""
        try:
            self.tfidf_vectorizer = joblib.load(filepath)
            self.feature_names = self.tfidf_vectorizer.get_feature_names_out()
            self.logger.info(f"TF-IDF vectorizer loaded from {filepath}")
        except Exception as e:
            self.logger.error(f"Error loading vectorizer: {str(e)}")
    
    def extract_all_features(self, df, fit=True):
        """
        Extract all features (TF-IDF + metadata) from dataset.
        
        Args:
            df (pd.DataFrame): Email dataset
            fit (bool): Whether to fit the vectorizer
            
        Returns:
            tuple: (combined_features, feature_names)
        """
        text_column = 'processed_text' if 'processed_text' in df.columns else 'text'
        texts = df[text_column].fillna('').astype(str).tolist()
        
        tfidf_features = self.create_tfidf_features(texts, fit=fit)
        
        metadata_features = self.extract_email_metadata_features(df)
        
        combined_features = self.combine_features(tfidf_features, metadata_features)
        
        tfidf_names = list(self.feature_names) if self.feature_names is not None else []
        metadata_names = list(metadata_features.columns)
        all_feature_names = tfidf_names + metadata_names
        
        self.logger.info(f"Extracted {combined_features.shape[1]} total features")
        self.logger.info(f"TF-IDF features: {tfidf_features.shape[1]}")
        self.logger.info(f"Metadata features: {len(metadata_names)}")
        
        return combined_features, all_feature_names


def create_feature_pipeline(df, target_column='label', test_size=0.2, random_state=42):
    """
    Create a complete feature extraction pipeline.
    
    Args:
        df (pd.DataFrame): Email dataset
        target_column (str): Name of target column
        test_size (float): Test set size
        random_state (int): Random state for reproducibility
        
    Returns:
        tuple: Training and testing features and labels
    """
    from sklearn.model_selection import train_test_split
    
    feature_extractor = FeatureExtractor()
    
    train_df, test_df = train_test_split(
        df, test_size=test_size, random_state=random_state, 
        stratify=df[target_column]
    )
    
    X_train, feature_names = feature_extractor.extract_all_features(train_df, fit=True)
    X_test, _ = feature_extractor.extract_all_features(test_df, fit=False)
    
    y_train = train_df[target_column].values
    y_test = test_df[target_column].values
    
    return X_train, X_test, y_train, y_test, feature_extractor


if __name__ == "__main__":
    # Example usage
    sample_data = {
        'text': [
            'Urgent! Your account will be suspended. Click here to verify.',
            'Meeting scheduled for tomorrow at 2 PM in conference room.',
            'Congratulations! You have won $1000. Claim now!',
            'Please find the attached report for your review.',
        ],
        'label': [1, 0, 1, 0]  # 1 = phishing, 0 = legitimate
    }
    
    df = pd.DataFrame(sample_data)
    
    feature_extractor = FeatureExtractor()
    
    features, feature_names = feature_extractor.extract_all_features(df)
    
    print(f"Feature matrix shape: {features.shape}")
    print(f"Number of feature names: {len(feature_names)}")
    print(f"Sample feature names: {feature_names[:10]}")
