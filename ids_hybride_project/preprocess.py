"""
Prétraitement des données - Pipeline identique à l'entraînement
Gère exactement 29 features: 26 numériques + 3 catégoriques
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
from config import (
    NUMERICAL_FEATURES, CATEGORICAL_FEATURES, ALL_FEATURES,
    SCALER_PATH, ENCODERS_PATH
)


class DataPreprocessor:
    """Préprocesseur pour les données UNSW-NB15"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_fitted = False
        
    def fit(self, df):
        """
        Ajuste le scaler et les label encoders sur les données d'entraînement
        
        Args:
            df: DataFrame contenant les features
        """
        # Vérifier que toutes les features sont présentes
        for feature in ALL_FEATURES:
            if feature not in df.columns:
                raise ValueError(f"Feature manquante: {feature}")
        
        # Ajuster le scaler sur les features numériques
        numerical_data = df[NUMERICAL_FEATURES].replace([np.inf, -np.inf], np.nan)
        numerical_data = numerical_data.fillna(0)
        self.scaler.fit(numerical_data)
        
        # Ajuster les label encoders pour les features catégoriques
        for feature in CATEGORICAL_FEATURES:
            le = LabelEncoder()
            # Convertir en string et normaliser la casse
            values = df[feature].astype(str).str.lower()
            # Pour 'state', garder en majuscules selon dataset original
            if feature == 'state':
                values = df[feature].astype(str).str.upper()
            le.fit(values)
            self.label_encoders[feature] = le
        
        self.is_fitted = True
        return self
    
    def transform(self, df):
        """
        Transforme les données en utilisant le scaler et encoders déjà ajustés
        
        Args:
            df: DataFrame contenant les features
            
        Returns:
            numpy array des features transformées
        """
        if not self.is_fitted:
            raise RuntimeError("Le préprocesseur doit être ajusté avant transformation")
        
        # Copie pour ne pas modifier l'original
        df_copy = df.copy()
        
        # Traiter les features numériques
        numerical_data = df_copy[NUMERICAL_FEATURES].replace([np.inf, -np.inf], np.nan)
        numerical_data = numerical_data.fillna(0)
        numerical_scaled = self.scaler.transform(numerical_data)
        
        # Traiter les features catégoriques
        categorical_encoded = []
        for feature in CATEGORICAL_FEATURES:
            le = self.label_encoders[feature]
            values = df_copy[feature].astype(str)
            
            # Normaliser la casse selon la feature
            if feature == 'state':
                values = values.str.upper()
            else:
                values = values.str.lower()
            
            # Gérer les valeurs inconnues
            encoded = []
            for val in values:
                try:
                    encoded.append(le.transform([val])[0])
                except ValueError:
                    # Valeur inconnue → rejeter cet échantillon
                    encoded.append(-1)
            categorical_encoded.append(encoded)
        
        # Combiner features numériques et catégoriques
        categorical_array = np.array(categorical_encoded).T
        X = np.hstack([numerical_scaled, categorical_array])
        
        return X
    
    def fit_transform(self, df):
        """Ajuste et transforme en une seule opération"""
        self.fit(df)
        return self.transform(df)
    
    def save(self, scaler_path=SCALER_PATH, encoders_path=ENCODERS_PATH):
        """Sauvegarde le scaler et les encoders"""
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.label_encoders, encoders_path)
        print(f"✓ Scaler sauvegardé: {scaler_path}")
        print(f"✓ LabelEncoders sauvegardés: {encoders_path}")
    
    def load(self, scaler_path=SCALER_PATH, encoders_path=ENCODERS_PATH):
        """Charge le scaler et les encoders depuis des fichiers"""
        self.scaler = joblib.load(scaler_path)
        self.label_encoders = joblib.load(encoders_path)
        self.is_fitted = True
        print(f"✓ Scaler chargé: {scaler_path}")
        print(f"✓ LabelEncoders chargés: {encoders_path}")
        return self
    
    def validate_sample(self, sample_dict):
        """
        Valide qu'un échantillon a exactement les 29 features requises
        
        Args:
            sample_dict: Dictionnaire avec les features
            
        Returns:
            bool: True si valide, False sinon
        """
        for feature in ALL_FEATURES:
            if feature not in sample_dict:
                return False
        return True


def load_and_preprocess_data(file_path, preprocessor=None):
    """
    Charge et prétraite un fichier CSV UNSW-NB15
    
    Args:
        file_path: Chemin du fichier CSV
        preprocessor: Préprocesseur existant (optionnel)
        
    Returns:
        X, y, preprocessor
    """
    # Charger le dataset
    df = pd.read_csv(file_path)
    
    # Features et target
    feature_columns = ALL_FEATURES + ['attack_cat']
    
    # Vérifier les colonnes disponibles
    available_cols = [c for c in feature_columns if c in df.columns]
    
    if len(available_cols) < len(feature_columns):
        print(f"⚠ Colonnes manquantes dans le dataset: {set(feature_columns) - set(available_cols)}")
    
    # Extraire features et target
    X_df = df[ALL_FEATURES].copy()
    y = df['attack_cat'] if 'attack_cat' in df.columns else pd.Series([0] * len(df))
    
    # Prétraitement
    if preprocessor is None:
        preprocessor = DataPreprocessor()
        X = preprocessor.fit_transform(X_df)
    else:
        X = preprocessor.transform(X_df)
    
    return X, y, preprocessor


if __name__ == "__main__":
    # Test du préprocesseur
    print("Test du module preprocess.py")
    print("=" * 50)
    
    # Créer un préprocesseur
    preprocessor = DataPreprocessor()
    
    # Données de test simulées
    test_data = {
        'dur': [0.001, 0.5, 1.2],
        'sbytes': [100, 5000, 10000],
        'dbytes': [200, 3000, 8000],
        'sttl': [64, 128, 255],
        'dttl': [64, 128, 255],
        'sload': [1000, 5000, 10000],
        'dload': [2000, 6000, 12000],
        'spkts': [10, 50, 100],
        'dpkts': [20, 60, 120],
        'rate': [100, 500, 1000],
        'sjit': [0.1, 0.5, 1.0],
        'djit': [0.2, 0.6, 1.2],
        'tcprtt': [0.01, 0.05, 0.1],
        'synack': [0.005, 0.02, 0.04],
        'ackdat': [0.008, 0.03, 0.06],
        'trans_depth': [1, 2, 3],
        'ct_srv_src': [5, 10, 15],
        'ct_state_ttl': [3, 6, 9],
        'ct_dst_ltm': [2, 4, 6],
        'ct_src_dport_ltm': [1, 3, 5],
        'ct_dst_sport_ltm': [2, 5, 8],
        'ct_dst_src_ltm': [3, 7, 11],
        'ct_flw_http_mthd': [0, 1, 2],
        'is_ftp_login': [0, 0, 1],
        'ct_ftp_cmd': [0, 1, 3],
        'ct_srv_dst': [4, 8, 12],
        'proto': ['tcp', 'udp', 'icmp'],
        'service': ['http', 'dns', '-'],
        'state': ['CON', 'FIN', 'REQ']
    }
    
    df_test = pd.DataFrame(test_data)
    
    print(f"Features numériques: {len(NUMERICAL_FEATURES)}")
    print(f"Features catégoriques: {len(CATEGORICAL_FEATURES)}")
    print(f"Total features: {len(ALL_FEATURES)}")
    print(f"\nShape du DataFrame de test: {df_test.shape}")
    
    # Transformation
    X = preprocessor.fit_transform(df_test)
    print(f"\nShape après transformation: {X.shape}")
    print(f"✓ Test réussi!")
