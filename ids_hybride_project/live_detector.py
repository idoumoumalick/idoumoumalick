"""
live_detector.py - Inférence ML temps réel
Charge model + scaler + encoders sauvegardés
Valide exactement 29 features, rejette les flux invalides sans planter
"""

import joblib
import numpy as np
import pandas as pd
from config import (
    MODEL_PATH, SCALER_PATH, ENCODERS_PATH,
    ML_CONFIDENCE_THRESHOLD, ATTACK_CATEGORIES,
    RISK_THRESHOLD_CRITICAL, RISK_THRESHOLD_HIGH, RISK_THRESHOLD_MEDIUM,
    ALL_FEATURES, NUMERICAL_FEATURES, CATEGORICAL_FEATURES
)


class LiveDetector:
    """Détection ML temps réel pour flux réseau"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoders = None
        self.is_loaded = False
        
    def load_models(self, model_path=MODEL_PATH, 
                    scaler_path=SCALER_PATH, 
                    encoders_path=ENCODERS_PATH):
        """
        Charge le modèle et les préprocesseurs sauvegardés
        
        Returns:
            bool: True si chargement réussi
        """
        try:
            # Charger le modèle
            self.model = joblib.load(model_path)
            print(f"✓ Modèle chargé: {model_path}")
            
            # Charger le scaler
            self.scaler = joblib.load(scaler_path)
            print(f"✓ Scaler chargé: {scaler_path}")
            
            # Charger les label encoders
            self.label_encoders = joblib.load(encoders_path)
            print(f"✓ LabelEncoders chargés: {encoders_path}")
            
            self.is_loaded = True
            return True
            
        except FileNotFoundError as e:
            print(f"✗ Fichier non trouvé: {e}")
            print("⚠ Assurez-vous d'avoir entraîné et sauvegardé le modèle")
            return False
        except Exception as e:
            print(f"✗ Erreur de chargement: {e}")
            return False
    
    def validate_flow(self, flow_data):
        """
        Valide qu'un flux a toutes les features requises
        
        Args:
            flow_data: dict du flux avec les features
            
        Returns:
            bool: True si valide
        """
        for feature in ALL_FEATURES:
            if feature not in flow_data:
                return False
        return True
    
    def preprocess_flow(self, flow_data):
        """
        Prétraite un flux pour l'inférence
        
        Args:
            flow_data: dict du flux avec les 29 features
            
        Returns:
            numpy array prétraitée ou None si invalide
        """
        if not self.is_loaded:
            return None
        
        try:
            # Créer DataFrame
            df = pd.DataFrame([flow_data])
            
            # Features numériques
            numerical_data = df[NUMERICAL_FEATURES].replace([np.inf, -np.inf], np.nan)
            numerical_data = numerical_data.fillna(0)
            numerical_scaled = self.scaler.transform(numerical_data)
            
            # Features catégoriques
            categorical_encoded = []
            for feature in CATEGORICAL_FEATURES:
                le = self.label_encoders[feature]
                values = df[feature].astype(str)
                
                # Normaliser la casse
                if feature == 'state':
                    values = values.str.upper()
                else:
                    values = values.str.lower()
                
                # Encoder avec gestion des valeurs inconnues
                encoded_val = -1
                for val in values:
                    try:
                        encoded_val = le.transform([val])[0]
                    except ValueError:
                        # Valeur inconnue → rejeter
                        return None
                
                categorical_encoded.append(encoded_val)
            
            # Combiner
            categorical_array = np.array(categorical_encoded).reshape(1, -1)
            X = np.hstack([numerical_scaled, categorical_array])
            
            return X
            
        except Exception as e:
            print(f"⚠ Erreur de prétraitement: {e}")
            return None
    
    def detect(self, flow_data):
        """
        Détecte une attaque sur un flux
        
        Args:
            flow_data: dict du flux avec les 29 features
            
        Returns:
            dict résultat ou None si flux invalide
        """
        if not self.is_loaded:
            return None
        
        # Valider les features
        if not self.validate_flow(flow_data):
            return None
        
        # Prétraiter
        X = self.preprocess_flow(flow_data)
        if X is None:
            return None
        
        try:
            # Prédiction
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            confidence = float(np.max(probabilities))
            
            # Vérifier le seuil de confiance
            if confidence < ML_CONFIDENCE_THRESHOLD:
                return None
            
            # Si c'est "Normal" et confiance faible, ne pas alerter
            if prediction == 'Normal' and confidence < 0.8:
                return {
                    'prediction': 'Normal',
                    'confidence': confidence,
                    'risk_level': 'low',
                    'is_attack': False
                }
            
            # Déterminer le niveau de risque
            risk_level = self._get_risk_level(confidence, prediction)
            
            # Probabilités par classe
            class_probs = {}
            for i, class_name in enumerate(ATTACK_CATEGORIES):
                class_probs[class_name] = float(probabilities[i])
            
            return {
                'prediction': prediction,
                'confidence': confidence,
                'risk_level': risk_level,
                'is_attack': prediction != 'Normal',
                'class_probabilities': class_probs
            }
            
        except Exception as e:
            print(f"⚠ Erreur d'inférence: {e}")
            return None
    
    def _get_risk_level(self, confidence, prediction):
        """Détermine le niveau de risque"""
        if prediction == 'Normal':
            return 'low'
        
        if confidence >= RISK_THRESHOLD_CRITICAL:
            return 'critical'
        elif confidence >= RISK_THRESHOLD_HIGH:
            return 'high'
        elif confidence >= RISK_THRESHOLD_MEDIUM:
            return 'medium'
        else:
            return 'low'
    
    def detect_batch(self, flows_data):
        """
        Détecte des attaques sur plusieurs flux
        
        Args:
            flows_data: list de dicts de flux
            
        Returns:
            list de résultats
        """
        results = []
        for flow in flows_data:
            result = self.detect(flow)
            if result:
                results.append({
                    'flow': flow,
                    'detection': result
                })
        return results


# Singleton global
_live_detector = None

def get_live_detector():
    """Retourne une instance singleton de LiveDetector"""
    global _live_detector
    if _live_detector is None:
        _live_detector = LiveDetector()
    return _live_detector


if __name__ == "__main__":
    # Test du détecteur live
    print("Test du module live_detector.py")
    print("=" * 50)
    
    detector = LiveDetector()
    
    # Tenter de charger les modèles
    if not detector.load_models():
        print("\n⚠ Modèles non disponibles (à entraîner d'abord)")
        print("Exécutez: python ml_supervised.py")
    else:
        print("\n✓ Modèles chargés avec succès")
        
        # Tester avec un flux fictif
        test_flow = {
            'dur': 0.5,
            'sbytes': 1000,
            'dbytes': 2000,
            'sttl': 64,
            'dttl': 64,
            'sload': 2000,
            'dload': 4000,
            'spkts': 10,
            'dpkts': 20,
            'rate': 60,
            'sjit': 0.5,
            'djit': 0.6,
            'tcprtt': 0.05,
            'synack': 0.02,
            'ackdat': 0.03,
            'trans_depth': 1,
            'ct_srv_src': 5,
            'ct_state_ttl': 3,
            'ct_dst_ltm': 2,
            'ct_src_dport_ltm': 1,
            'ct_dst_sport_ltm': 2,
            'ct_dst_src_ltm': 3,
            'ct_flw_http_mthd': 0,
            'is_ftp_login': 0,
            'ct_ftp_cmd': 0,
            'ct_srv_dst': 4,
            'proto': 'tcp',
            'service': 'http',
            'state': 'CON'
        }
        
        print("\n[Test] Détection sur un flux HTTP...")
        result = detector.detect(test_flow)
        
        if result:
            print(f"  Prédiction: {result['prediction']}")
            print(f"  Confiance: {result['confidence']:.2%}")
            print(f"  Risque: {result['risk_level']}")
            print(f"  Attaque: {result['is_attack']}")
        else:
            print("  ⚠ Flux invalide ou confiance insuffisante")
    
    print("\n✓ Test terminé!")
