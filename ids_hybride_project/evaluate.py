"""
evaluate.py - Script d'évaluation et benchmark du modèle
Calcule toutes les métriques: Accuracy, Precision, Recall, F1-Score
Génère un rapport complet avec matrice de confusion
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc
)
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from config import DATA_TESTING_PATH, ATTACK_CATEGORIES
from preprocess import DataPreprocessor
from ml_supervised import MLSupervisedDetector


def evaluate_model():
    """
    Évalue le modèle Random Forest sur le dataset de test
    
    Returns:
        dict: Métriques complètes
    """
    print("=" * 70)
    print("ÉVALUATION DU MODÈLE IDS HYBRIDE")
    print("=" * 70)
    
    # Charger le modèle et les préprocesseurs
    print("\n[1/5] Chargement des modèles...")
    try:
        model = joblib.load('models/random_forest_model.joblib')
        scaler = joblib.load('models/scaler.joblib')
        label_encoders = joblib.load('models/label_encoders.joblib')
        print("✓ Modèles chargés avec succès")
    except FileNotFoundError as e:
        print(f"✗ Modèles non trouvés: {e}")
        print("⚠ Veuillez d'abord entraîner le modèle: python ml_supervised.py")
        return None
    
    # Charger les données de test
    print("\n[2/5] Chargement du dataset de test...")
    try:
        df_test = pd.read_csv(DATA_TESTING_PATH)
        print(f"   Dataset chargé: {len(df_test)} échantillons")
    except FileNotFoundError:
        print(f"⚠ Fichier de test non trouvé: {DATA_TESTING_PATH}")
        print("   Utilisation d'un split du dataset d'entraînement")
        df_test = pd.read_csv('data/UNSW_NB15_training-set.csv')
        df_test = df_test.sample(frac=0.3, random_state=42)
    
    # Prétraitement
    print("\n[3/5] Prétraitement des données...")
    preprocessor = DataPreprocessor()
    preprocessor.scaler = scaler
    preprocessor.label_encoders = label_encoders
    preprocessor.is_fitted = True
    
    from config import ALL_FEATURES
    X_test_df = df_test[ALL_FEATURES].copy()
    y_test = df_test['attack_cat'] if 'attack_cat' in df_test.columns else pd.Series([0] * len(df_test))
    
    X_test = preprocessor.transform(X_test_df)
    print(f"   Features: {X_test.shape[1]}, Échantillons: {X_test.shape[0]}")
    
    # Prédictions
    print("\n[4/5] Exécution des prédictions...")
    detector = MLSupervisedDetector()
    detector.model = model
    detector.preprocessor = preprocessor
    detector.is_trained = True
    
    predictions, confidences = detector.predict(X_test)
    print(f"   Prédictions générées: {len(predictions)}")
    
    # Calcul des métriques
    print("\n[5/5] Calcul des métriques...")
    
    # Métriques globales
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, average='weighted', zero_division=0)
    recall = recall_score(y_test, predictions, average='weighted', zero_division=0)
    f1 = f1_score(y_test, predictions, average='weighted', zero_division=0)
    
    # Matrice de confusion
    cm = confusion_matrix(y_test, predictions, labels=ATTACK_CATEGORIES)
    
    # Rapport détaillé par classe
    report = classification_report(y_test, predictions, 
                                   target_names=ATTACK_CATEGORIES, 
                                   zero_division=0,
                                   output_dict=True)
    
    results = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm,
        'classification_report': report,
        'predictions': predictions,
        'actual': y_test.values,
        'confidences': confidences
    }
    
    # Affichage des résultats
    print("\n" + "=" * 70)
    print("RÉSULTATS DE L'ÉVALUATION")
    print("=" * 70)
    
    print(f"\n📊 MÉTRIQUES GLOBALES")
    print(f"   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    print(f"   F1-Score:  {f1:.4f}")
    
    print(f"\n📋 RAPPORT PAR CLASSE")
    print(classification_report(y_test, predictions, 
                                target_names=ATTACK_CATEGORIES, 
                                zero_division=0))
    
    # Top features
    print(f"\n🔝 IMPORTANCE DES FEATURES (Top 15)")
    feature_importance = list(zip(ALL_FEATURES, model.feature_importances_))
    feature_importance.sort(key=lambda x: x[1], reverse=True)
    
    for i, (feature, importance) in enumerate(feature_importance[:15]):
        bar = "█" * int(importance * 50)
        print(f"   {i+1:2}. {feature:20s}: {importance:.4f} {bar}")
    
    # Sauvegarder les résultats
    print("\n" + "=" * 70)
    print("SAUVEGARDE DES RÉSULTATS")
    print("=" * 70)
    
    # Sauvegarder dans un fichier
    results_df = pd.DataFrame({
        'metric': ['Accuracy', 'Precision', 'Recall', 'F1-Score'],
        'value': [accuracy, precision, recall, f1]
    })
    results_df.to_csv('evaluation_results.csv', index=False)
    print("✓ Résultats sauvegardés: evaluation_results.csv")
    
    # Générer la matrice de confusion visuelle
    try:
        plt.figure(figsize=(12, 10))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=ATTACK_CATEGORIES,
                    yticklabels=ATTACK_CATEGORIES)
        plt.title('Matrice de Confusion')
        plt.xlabel('Prédit')
        plt.ylabel('Réel')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig('confusion_matrix.png', dpi=150)
        print("✓ Matrice de confusion sauvegardée: confusion_matrix.png")
        plt.close()
    except Exception as e:
        print(f"⚠ Impossible de générer la matrice visuelle: {e}")
    
    return results


def benchmark_models():
    """Compare différents modèles (optionnel)"""
    print("\n" + "=" * 70)
    print("BENCHMARK DE MODÈLES (Optionnel)")
    print("=" * 70)
    
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import GaussianNB
    
    # Charger les données
    try:
        df = pd.read_csv('data/UNSW_NB15_training-set.csv')
        df = df.sample(n=50000, random_state=42)  # Échantillon pour rapidité
    except FileNotFoundError:
        print("⚠ Dataset non disponible pour le benchmark")
        return
    
    preprocessor = DataPreprocessor()
    from config import ALL_FEATURES
    X = df[ALL_FEATURES].copy()
    y = df['attack_cat']
    
    X_processed = preprocessor.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(
        X_processed, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Modèles à comparer
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=50, max_depth=15, n_jobs=-1),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=50, max_depth=10),
        'Logistic Regression': LogisticRegression(max_iter=1000, n_jobs=-1),
        'Naive Bayes': GaussianNB()
    }
    
    results = []
    
    for name, clf in models.items():
        print(f"\nEntraînement de {name}...")
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        
        acc = accuracy_score(y_test, preds)
        f1 = f1_score(y_test, preds, average='weighted', zero_division=0)
        
        results.append({
            'Model': name,
            'Accuracy': acc,
            'F1-Score': f1
        })
        
        print(f"   Accuracy: {acc:.4f}, F1-Score: {f1:.4f}")
    
    # Tableau comparatif
    print("\n" + "=" * 70)
    print("COMPARAISON DES MODÈLES")
    print("=" * 70)
    
    results_df = pd.DataFrame(results)
    print(results_df.to_string(index=False))
    
    # Sauvegarder
    results_df.to_csv('benchmark_results.csv', index=False)
    print("\n✓ Benchmark sauvegardé: benchmark_results.csv")


if __name__ == "__main__":
    # Évaluer le modèle principal
    results = evaluate_model()
    
    if results:
        print("\n" + "=" * 70)
        print("✓ ÉVALUATION TERMINÉE AVEC SUCCÈS")
        print("=" * 70)
        
        # Résumé final
        print(f"\n📈 RÉSUMÉ")
        print(f"   Le modèle Random Forest atteint {results['accuracy']*100:.2f}% d'accuracy")
        print(f"   avec un F1-Score de {results['f1_score']:.4f}")
        print(f"   sur {len(results['predictions'])} échantillons de test")
    else:
        print("\n✗ Évaluation échouée")
    
    # Optionnel: Benchmark
    # benchmark_models()
