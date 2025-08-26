"""
Model training module for phishing email detection.
Implements Random Forest and SVM classifiers with hyperparameter tuning.
"""

import pandas as pd
import numpy as np
import joblib
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.model_selection import GridSearchCV, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)
from sklearn.pipeline import Pipeline
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import os

class PhishingDetectionTrainer:
    """
    Machine learning trainer for phishing email detection.
    """
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.best_models = {}
        self.training_history = {}
        self.logger = logging.getLogger(__name__)

    def create_random_forest_model(self, **kwargs):
        default_params = {
            'n_estimators': 100,
            'max_depth': None,
            'min_samples_split': 2,
            'min_samples_leaf': 1,
            'random_state': self.random_state,
            'n_jobs': -1
        }
        default_params.update(kwargs)
        return RandomForestClassifier(**default_params)

    def create_svm_model(self, **kwargs):
        default_params = {
            'kernel': 'rbf',
            'C': 1.0,
            'gamma': 'scale',
            'random_state': self.random_state,
            'probability': True
        }
        default_params.update(kwargs)
        return SVC(**default_params)

    def tune_random_forest(self, X_train, y_train, cv=5):
        self.logger.info("Tuning Random Forest hyperparameters...")
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'max_features': ['sqrt', 'log2', None]
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
        self.logger.info(f"Best Random Forest parameters: {grid_search.best_params_}")
        self.logger.info(f"Best Random Forest F1 score: {grid_search.best_score_:.4f}")
        self.best_models['random_forest'] = grid_search.best_estimator_
        return grid_search

    def tune_svm(self, X_train, y_train, cv=5):
        self.logger.info("Tuning SVM hyperparameters...")
        param_grid = {
            'C': [0.1, 1, 10, 100],
            'gamma': ['scale', 'auto', 0.001, 0.01, 0.1, 1],
            'kernel': ['rbf', 'linear', 'poly']
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
        grid_search.fit(X_train, y_train)
        self.logger.info(f"Best SVM parameters: {grid_search.best_params_}")
        self.logger.info(f"Best SVM F1 score: {grid_search.best_score_:.4f}")
        self.best_models['svm'] = grid_search.best_estimator_
        return grid_search

    def train_models(self, X_train, y_train, tune_hyperparameters=True):
        self.logger.info("Starting model training...")
        if tune_hyperparameters:
            self.tune_random_forest(X_train, y_train)
            self.tune_svm(X_train, y_train)
        else:
            self.logger.info("Training with default parameters...")
            rf = self.create_random_forest_model()
            rf.fit(X_train, y_train)
            self.best_models['random_forest'] = rf
            svm = self.create_svm_model()
            svm.fit(X_train, y_train)
            self.best_models['svm'] = svm
        self.logger.info("Model training completed!")

    def evaluate_model(self, model, X_test, y_test, model_name):
        self.logger.info(f"Evaluating {model_name}...")
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
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
        print(f"\nClassification Report for {model_name}:")
        print(classification_report(y_test, y_pred))
        return metrics

    def evaluate_all_models(self, X_test, y_test):
        results = {}
        for model_name, model in self.best_models.items():
            metrics = self.evaluate_model(model, X_test, y_test, model_name)
            results[model_name] = metrics
        self.compare_models(results)
        return results

    def compare_models(self, results):
        print("\nMODEL COMPARISON:")
        print("=" * 50)
        comparison_df = pd.DataFrame(results).T
        comparison_df = comparison_df.round(4)
        print(comparison_df)
        print("\nBest models by metric:")
        for metric in comparison_df.columns:
            best_model = comparison_df[metric].idxmax()
            best_score = comparison_df[metric].max()
            print(f"{metric.capitalize()}: {best_model} ({best_score:.4f})")

    def plot_confusion_matrices(self, X_test, y_test):
        n_models = len(self.best_models)
        fig, axes = plt.subplots(1, n_models, figsize=(5 * n_models, 4))
        if n_models == 1:
            axes = [axes]
        for idx, (model_name, model) in enumerate(self.best_models.items()):
            y_pred = model.predict(X_test)
            cm = confusion_matrix(y_test, y_pred)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[idx])
            axes[idx].set_title(f'{model_name.replace("_", " ").title()} Confusion Matrix')
            axes[idx].set_xlabel('Predicted')
            axes[idx].set_ylabel('Actual')
        plt.tight_layout()
        plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
        plt.show()

    def plot_feature_importance(self, feature_names, top_n=20):
        if 'random_forest' not in self.best_models:
            self.logger.warning("Random Forest model not available for feature importance plot")
            return
        rf_model = self.best_models['random_forest']
        if hasattr(rf_model, 'feature_importances_'):
            importances = rf_model.feature_importances_
            # Defensive: don't index out of bounds
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
            plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
            plt.show()

    def save_models(self, model_dir='data/models/'):
        os.makedirs(model_dir, exist_ok=True)
        for model_name, model in self.best_models.items():
            model_path = os.path.join(model_dir, f'{model_name}_model.pkl')
            joblib.dump(model, model_path)
            self.logger.info(f"Saved {model_name} model to {model_path}")

    def load_models(self, model_dir='data/models/'):
        model_files = {
            'random_forest': 'random_forest_model.pkl',
            'svm': 'svm_model.pkl'
        }
        for model_name, filename in model_files.items():
            model_path = os.path.join(model_dir, filename)
            if os.path.exists(model_path):
                self.best_models[model_name] = joblib.load(model_path)
                self.logger.info(f"Loaded {model_name} model from {model_path}")
            else:
                self.logger.warning(f"Model file not found: {model_path}")

    def cross_validate_models(self, X_train, y_train, cv=5):
        self.logger.info("Performing cross-validation...")
        cv_results = {}
        for model_name, model in self.best_models.items():
            scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='f1')
            cv_results[model_name] = {
                'mean_f1': scores.mean(),
                'std_f1': scores.std(),
                'scores': scores
            }
            print(f"\n{model_name.upper()} Cross-Validation Results:")
            print(f"F1 Score: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
        return cv_results

def train_phishing_detection_models(X_train, X_test, y_train, y_test, feature_names=None, save_models=True):
    trainer = PhishingDetectionTrainer()
    trainer.train_models(X_train, y_train, tune_hyperparameters=True)
    trainer.evaluate_all_models(X_test, y_test)
    trainer.cross_validate_models(X_train, y_train)
    trainer.plot_confusion_matrices(X_test, y_test)
    # Safe feature_names usage
    if feature_names is not None and len(feature_names) > 0:
        trainer.plot_feature_importance(feature_names)
    if save_models:
        trainer.save_models()
    return trainer

if __name__ == "__main__":
    from sklearn.datasets import make_classification
    X, y = make_classification(
        n_samples=1000, n_features=100, n_informative=50,
        n_redundant=20, n_clusters_per_class=1, random_state=42
    )
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    feature_names = [f'Feature_{i}' for i in range(X_train.shape[1])]
    trainer = train_phishing_detection_models(
        X_train, X_test, y_train, y_test, feature_names, save_models=False
    )
    print("Training completed successfully!")
