"""
Module Machine Learning Supervisé - Random Forest
Entraîné sur le dataset UNSW-NB15 pour détecter 9 catégories d'attaques
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import joblib
import pandas as pd
from config import (
    MODEL_PATH, SCALER_PATH, ENCODERS_PATH,
    DATA_TRAINING_PATH, ML_CONFIDENCE_THRESHOLD,
    ATTACK_CATEGORIES
)
from preprocess import DataPreprocessor, load_and_preprocess_data


class MLSupervisedDetector:
    """Détection d'intrusions par Machine Learning (Random Forest)"""
    
    def __init__(self):
        self.model = None
        self.preprocessor = None
        self.is_trained = False
        self.class_names = ATTACK_CATEGORIES
        
    def train(self, X_train, y_train):
        """
        Entraîne le modèle Random Forest
        
        Args:
            X_train: Features d'entraînement (déjà prétraitées)
            y_train: Labels d'entraînement
        """
        print("Entraînement du modèle Random Forest...")
        
        # Création du modèle avec hyperparamètres optimisés
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        # Entraînement
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        print(f"✓ Modèle entraîné avec {len(self.model.estimators_)} arbres")
        return self
    
    def predict(self, X):
        """
        Prédit les classes pour des échantillons
        
        Args:
            X: Features prétraitées
            
        Returns:
            predictions, confidences
        """
        if not self.is_trained:
            raise RuntimeError("Le modèle doit être entraîné avant utilisation")
        
        # Prédictions
        predictions = self.model.predict(X)
        
        # Probabilités (confiance)
        probabilities = self.model.predict_proba(X)
        confidences = np.max(probabilities, axis=1)
        
        return predictions, confidences
    
    def predict_sample(self, features_dict):
        """
        Prédit la classe pour un seul échantillon
        
        Args:
            features_dict: Dictionnaire avec les 29 features
            
        Returns:
            prediction, confidence, risk_level ou None si features invalides
        """
        if not self.is_trained:
            raise RuntimeError("Le modèle doit être entraîné avant utilisation")
        
        # Valider les features
        if not self.preprocessor.validate_sample(features_dict):
            return None, None, None
        
        # Créer DataFrame
        df_sample = pd.DataFrame([features_dict])
        
        # Prétraitement
        try:
            X = self.preprocessor.transform(df_sample)
        except Exception as e:
            print(f"⚠ Erreur de prétraitement: {e}")
            return None, None, None
        
        # Prédiction
        predictions, confidences = self.predict(X)
        
        prediction = predictions[0]
        confidence = confidences[0]
        
        # Déterminer le niveau de risque
        risk_level = self._get_risk_level(confidence, prediction)
        
        return prediction, confidence, risk_level
    
    def _get_risk_level(self, confidence, prediction):
        """
        Détermine le niveau de risque basé sur la confiance et la prédiction
        
        Args:
            confidence: Score de confiance du modèle
            prediction: Classe prédite
            
        Returns:
            risk_level: 'low', 'medium', 'high', 'critical'
        """
        # Si c'est "Normal", risque faible
        if prediction == 'Normal':
            return 'low'
        
        # Basé sur la confiance
        from config import RISK_THRESHOLD_CRITICAL, RISK_THRESHOLD_HIGH, RISK_THRESHOLD_MEDIUM
        
        if confidence >= RISK_THRESHOLD_CRITICAL:
            return 'critical'
        elif confidence >= RISK_THRESHOLD_HIGH:
            return 'high'
        elif confidence >= RISK_THRESHOLD_MEDIUM:
            return 'medium'
        else:
            return 'low'
    
    def evaluate(self, X_test, y_test):
        """
        Évalue le modèle sur des données de test
        
        Args:
            X_test: Features de test
            y_test: Labels de test
            
        Returns:
            dict de métriques
        """
        if not self.is_trained:
            raise RuntimeError("Le modèle doit être entraîné avant évaluation")
        
        predictions, _ = self.predict(X_test)
        
        # Métriques globales
        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions, average='weighted', zero_division=0)
        recall = recall_score(y_test, predictions, average='weighted', zero_division=0)
        f1 = f1_score(y_test, predictions, average='weighted', zero_division=0)
        
        # Matrice de confusion
        cm = confusion_matrix(y_test, predictions, labels=self.class_names)
        
        # Rapport détaillé
        report = classification_report(y_test, predictions, target_names=self.class_names, zero_division=0)
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm,
            'classification_report': report
        }
    
    def save(self, model_path=MODEL_PATH):
        """Sauvegarde le modèle entraîné"""
        if not self.is_trained:
            raise RuntimeError("Aucun modèle à sauvegarder")
        
        joblib.dump(self.model, model_path)
        print(f"✓ Modèle sauvegardé: {model_path}")
    
    def load(self, model_path=MODEL_PATH):
        """Charge un modèle pré-entraîné"""
        self.model = joblib.load(model_path)
        self.is_trained = True
        print(f"✓ Modèle chargé: {model_path}")
        return self
    
    def set_preprocessor(self, preprocessor):
        """Définit le préprocesseur à utiliser"""
        self.preprocessor = preprocessor
    
    def get_feature_importance(self):
        """Retourne l'importance des features"""
        if not self.is_trained:
            raise RuntimeError("Le modèle doit être entraîné")
        
        from config import ALL_FEATURES
        
        importance = self.model.feature_importances_
        feature_importance = list(zip(ALL_FEATURES, importance))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        return feature_importance


def train_model_from_csv(training_path=DATA_TRAINING_PATH):
    """
    Entraîne un modèle complet depuis le fichier CSV
    
    Returns:
        detector, preprocessor, metrics
    """
    print("=" * 60)
    print("ENTRAÎNEMENT DU MODÈLE RANDOM FOREST")
    print("=" * 60)
    
    # Charger et prétraiter les données
    print("\n[1/4] Chargement des données...")
    X, y, preprocessor = load_and_preprocess_data(training_path)
    print(f"   Shape des données: {X.shape}")
    print(f"   Distribution des classes:\n{y.value_counts()}")
    
    # Split train/test
    print("\n[2/4] Séparation train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Train: {X_train.shape}, Test: {X_test.shape}")
    
    # Entraînement
    print("\n[3/4] Entraînement du modèle...")
    detector = MLSupervisedDetector()
    detector.set_preprocessor(preprocessor)
    detector.train(X_train, y_train)
    
    # Évaluation
    print("\n[4/4] Évaluation du modèle...")
    metrics = detector.evaluate(X_test, y_test)
    
    print("\n" + "=" * 60)
    print("RÉSULTATS DE L'ÉVALUATION")
    print("=" * 60)
    print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1-Score:  {metrics['f1_score']:.4f}")
    print("\n" + "-" * 60)
    print("Rapport de classification:")
    print(metrics['classification_report'])
    
    # Sauvegarder
    print("\n" + "=" * 60)
    print("SAUVEGARDE DES MODÈLES")
    print("=" * 60)
    detector.save()
    preprocessor.save()
    
    # Feature importance
    print("\n" + "=" * 60)
    print("IMPORTANCE DES FEATURES (Top 10)")
    print("=" * 60)
    feature_importance = detector.get_feature_importance()
    for i, (feature, importance) in enumerate(feature_importance[:10]):
        print(f"{i+1:2}. {feature:20s}: {importance:.4f}")
    
    return detector, preprocessor, metrics


if __name__ == "__main__":
    # Entraîner le modèle
    try:
        detector, preprocessor, metrics = train_model_from_csv()
        print("\n✓ Entraînement terminé avec succès!")
    except FileNotFoundError as e:
        print(f"\n⚠ Fichier de données non trouvé: {e}")
        print("Assurez-vous que le dataset UNSW-NB15 est présent dans data/")
    except Exception as e:
        print(f"\n✗ Erreur lors de l'entraînement: {e}")
