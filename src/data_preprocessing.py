"""
Data preprocessing module for phishing email detection.
Handles email text cleaning, normalization, and feature preparation.
"""

import re
import string
import nltk
import pandas as pd
import numpy as np
from bs4 import BeautifulSoup
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.stem.porter import PorterStemmer
from email import message_from_string
from email.utils import parseaddr
import logging

# Download required NLTK data
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)
nltk.download('omw-1.4', quiet=True)

class EmailPreprocessor:
    """
    Comprehensive email preprocessing class for phishing detection.
    """
    
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        self.lemmatizer = WordNetLemmatizer()
        self.stemmer = PorterStemmer()
        self.logger = logging.getLogger(__name__)
        
    def extract_email_content(self, email_text):
        """
        Extract structured content from raw email text.
        
        Args:
            email_text (str): Raw email content
            
        Returns:
            dict: Structured email data
        """
        try:
            # Parse email message
            msg = message_from_string(email_text)
            
            # Extract basic email components
            email_data = {
                'subject': msg.get('Subject', ''),
                'sender': msg.get('From', ''),
                'receiver': msg.get('To', ''),
                'date': msg.get('Date', ''),
                'body': '',
                'urls': [],
                'sender_email': '',
                'sender_name': ''
            }
            
            # Extract sender information
            if email_data['sender']:
                sender_name, sender_email = parseaddr(email_data['sender'])
                email_data['sender_email'] = sender_email
                email_data['sender_name'] = sender_name
            
            # Extract email body
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        email_data['body'] += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif part.get_content_type() == "text/html":
                        html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        # Convert HTML to plain text
                        soup = BeautifulSoup(html_content, 'html.parser')
                        email_data['body'] += soup.get_text()
            else:
                email_data['body'] = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            # Extract URLs from email body
            email_data['urls'] = self.extract_urls(email_data['body'])
            
            return email_data
            
        except Exception as e:
            self.logger.error(f"Error extracting email content: {str(e)}")
            return {
                'subject': '',
                'sender': '',
                'receiver': '',
                'date': '',
                'body': email_text,
                'urls': self.extract_urls(email_text),
                'sender_email': '',
                'sender_name': ''
            }
    
    def extract_urls(self, text):
        """
        Extract URLs from text using regex patterns.
        
        Args:
            text (str): Input text
            
        Returns:
            list: List of URLs found in text
        """
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        return url_pattern.findall(text)
    
    def clean_text(self, text):
        """
        Clean and normalize text for processing.
        
        Args:
            text (str): Input text
            
        Returns:
            str: Cleaned text
        """
        if not isinstance(text, str):
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove HTML tags if any
        text = BeautifulSoup(text, 'html.parser').get_text()
        
        # Remove URLs
        text = re.sub(r'http[s]?://\S+', ' ', text)
        
        # Remove email addresses
        text = re.sub(r'\S+@\S+', ' ', text)
        
        # Remove special characters and digits
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()
    
    def tokenize_text(self, text):
        """
        Tokenize text into individual words.
        
        Args:
            text (str): Input text
            
        Returns:
            list: List of tokens
        """
        return word_tokenize(text)
    
    def remove_stopwords(self, tokens):
        """
        Remove stopwords from token list.
        
        Args:
            tokens (list): List of tokens
            
        Returns:
            list: Filtered tokens
        """
        return [token for token in tokens if token not in self.stop_words and len(token) > 2]
    
    def lemmatize_tokens(self, tokens):
        """
        Lemmatize tokens to their root form.
        
        Args:
            tokens (list): List of tokens
            
        Returns:
            list: Lemmatized tokens
        """
        return [self.lemmatizer.lemmatize(token) for token in tokens]
    
    def stem_tokens(self, tokens):
        """
        Stem tokens using Porter Stemmer.
        
        Args:
            tokens (list): List of tokens
            
        Returns:
            list: Stemmed tokens
        """
        return [self.stemmer.stem(token) for token in tokens]
    
    def preprocess_text(self, text, use_stemming=True):
        """
        Complete text preprocessing pipeline.
        
        Args:
            text (str): Input text
            use_stemming (bool): Whether to use stemming or lemmatization
            
        Returns:
            str: Preprocessed text
        """
        # Clean text
        clean_text = self.clean_text(text)
        
        # Tokenize
        tokens = self.tokenize_text(clean_text)
        
        # Remove stopwords
        filtered_tokens = self.remove_stopwords(tokens)
        
        # Apply stemming or lemmatization
        if use_stemming:
            processed_tokens = self.stem_tokens(filtered_tokens)
        else:
            processed_tokens = self.lemmatize_tokens(filtered_tokens)
        
        return ' '.join(processed_tokens)
    
    def preprocess_email_dataset(self, df, text_column='text', label_column='label'):
        """
        Preprocess an entire email dataset.
        
        Args:
            df (pd.DataFrame): Input dataframe
            text_column (str): Name of text column
            label_column (str): Name of label column
            
        Returns:
            pd.DataFrame: Preprocessed dataframe
        """
        self.logger.info(f"Preprocessing {len(df)} email samples...")
        
        # Create a copy of the dataframe
        processed_df = df.copy()
        
        # Preprocess text column
        processed_df['processed_text'] = processed_df[text_column].apply(
            lambda x: self.preprocess_text(str(x))
        )
        
        # Extract additional features
        processed_df['email_length'] = processed_df[text_column].apply(len)
        processed_df['word_count'] = processed_df['processed_text'].apply(
            lambda x: len(x.split())
        )
        processed_df['url_count'] = processed_df[text_column].apply(
            lambda x: len(self.extract_urls(str(x)))
        )
        
        # Remove empty processed texts
        processed_df = processed_df[processed_df['processed_text'].str.len() > 0]
        
        self.logger.info(f"Preprocessing complete. {len(processed_df)} samples remaining.")
        
        return processed_df
    
    def extract_email_features(self, email_text):
        """
        Extract additional features from email for better classification.
        
        Args:
            email_text (str): Email content
            
        Returns:
            dict: Dictionary of extracted features
        """
        features = {}
        
        # Basic text features
        features['char_count'] = len(email_text)
        features['word_count'] = len(email_text.split())
        features['sentence_count'] = len(re.findall(r'[.!?]+', email_text))
        
        # URL features
        urls = self.extract_urls(email_text)
        features['url_count'] = len(urls)
        features['has_shortened_url'] = any(
            domain in url for url in urls 
            for domain in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
        )
        
        # Suspicious pattern features
        features['has_ip_address'] = bool(re.search(r'\d+\.\d+\.\d+\.\d+', email_text))
        features['excessive_caps'] = len(re.findall(r'[A-Z]{3,}', email_text))
        features['exclamation_count'] = email_text.count('!')
        features['question_count'] = email_text.count('?')
        
        # Keyword-based features
        suspicious_keywords = [
            'urgent', 'verify', 'suspended', 'click here', 'limited time',
            'act now', 'congratulations', 'winner', 'lottery', 'prize'
        ]
        
        features['suspicious_keyword_count'] = sum(
            1 for keyword in suspicious_keywords if keyword in email_text.lower()
        )
        
        return features

def load_and_preprocess_data(file_path, text_column='text', label_column='label'):
    """
    Load and preprocess email dataset from CSV file.
    
    Args:
        file_path (str): Path to CSV file
        text_column (str): Name of text column
        label_column (str): Name of label column
        
    Returns:
        pd.DataFrame: Preprocessed dataframe
    """
    # Load data
    df = pd.read_csv(file_path)
    
    # Initialize preprocessor
    preprocessor = EmailPreprocessor()
    
    # Preprocess data
    processed_df = preprocessor.preprocess_email_dataset(df, text_column, label_column)
    
    return processed_df

if __name__ == "__main__":
    # Example usage
    sample_email = """
    Subject: URGENT: Verify Your Account
    
    Dear Customer,
    
    Your account has been suspended due to suspicious activity. 
    Click here to verify: http://fake-bank.com/verify
    
    Act now or lose access permanently!
    
    Best regards,
    Customer Service
    """
    
    preprocessor = EmailPreprocessor()
    
    # Extract email content
    email_data = preprocessor.extract_email_content(sample_email)
    print("Email Data:", email_data)
    
    # Preprocess text
    processed_text = preprocessor.preprocess_text(sample_email)
    print("Processed Text:", processed_text)
    
    # Extract features
    features = preprocessor.extract_email_features(sample_email)
    print("Features:", features)