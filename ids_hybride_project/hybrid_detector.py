"""
Détecteur Hybride - Fusion des méthodes Rule-Based et ML
Combine les résultats des deux approches pour une détection plus fiable
"""

from datetime import datetime
from config import ML_CONFIDENCE_THRESHOLD, ATTACK_CATEGORIES


class HybridDetector:
    """
    Détecteur hybride combinant Rule-Based et Machine Learning
    
    Stratégie de fusion:
    - Si les deux méthodes détectent une attaque → confirmation mutuelle (critical)
    - Si seulement Rule-Based détecte → alerte rule_based (high)
    - Si seulement ML détecte avec haute confiance → alerte ml (high)
    - Si ML détecte avec confiance moyenne → alerte ml (medium)
    """
    
    def __init__(self, rule_detector=None, ml_detector=None):
        self.rule_detector = rule_detector
        self.ml_detector = ml_detector
        self.alerts = []
        
    def set_rule_detector(self, rule_detector):
        """Définit le détecteur Rule-Based"""
        self.rule_detector = rule_detector
        
    def set_ml_detector(self, ml_detector):
        """Définit le détecteur ML"""
        self.ml_detector = ml_detector
        
    def analyze_flow(self, flow_data):
        """
        Analyse un flux réseau avec les deux méthodes et fusionne les résultats
        
        Args:
            flow_data: dict avec toutes les features nécessaires
                       (src_ip, dst_ip, ports, + 29 features pour ML)
                       
        Returns:
            hybrid_alert ou None
        """
        rule_alerts = []
        ml_alert = None
        
        # Détection Rule-Based
        if self.rule_detector:
            rule_alerts = self.rule_detector.analyze_flow(flow_data)
        
        # Détection ML
        if self.ml_detector and self._has_ml_features(flow_data):
            ml_prediction, ml_confidence, ml_risk = self._detect_ml(flow_data)
            
            if ml_prediction and ml_prediction != 'Normal' and ml_confidence >= ML_CONFIDENCE_THRESHOLD:
                ml_alert = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': flow_data.get('src_ip', ''),
                    'dst_ip': flow_data.get('dst_ip', ''),
                    'attack_type': ml_prediction,
                    'detection_method': 'ml',
                    'confidence': ml_confidence,
                    'risk_level': ml_risk,
                    'description': f"Attaque '{ml_prediction}' détectée par ML (confiance: {ml_confidence:.2%})",
                    'details': {
                        'prediction': ml_prediction,
                        'confidence': ml_confidence,
                        'all_predictions': self._get_all_class_probabilities(flow_data)
                    }
                }
        
        # Fusion des résultats
        hybrid_alert = self._fuse_alerts(rule_alerts, ml_alert, flow_data)
        
        if hybrid_alert:
            self.alerts.append(hybrid_alert)
        
        return hybrid_alert
    
    def _has_ml_features(self, flow_data):
        """Vérifie si le flux a toutes les features pour le ML"""
        required_features = [
            'dur', 'sbytes', 'dbytes', 'sttl', 'dttl',
            'proto', 'service', 'state'
        ]
        return all(f in flow_data for f in required_features)
    
    def _detect_ml(self, flow_data):
        """Exécute la détection ML"""
        try:
            # Extraire les 29 features
            features_dict = self._extract_ml_features(flow_data)
            prediction, confidence, risk_level = self.ml_detector.predict_sample(features_dict)
            return prediction, confidence, risk_level
        except Exception as e:
            print(f"⚠ Erreur détection ML: {e}")
            return None, None, None
    
    def _extract_ml_features(self, flow_data):
        """Extrait les 29 features du flux"""
        from config import ALL_FEATURES
        
        features = {}
        for feature in ALL_FEATURES:
            features[feature] = flow_data.get(feature, 0)
        
        return features
    
    def _get_all_class_probabilities(self, flow_data):
        """Récupère les probabilités pour toutes les classes"""
        try:
            features_dict = self._extract_ml_features(flow_data)
            df_sample = __import__('pandas').DataFrame([features_dict])
            X = self.ml_detector.preprocessor.transform(df_sample)
            probabilities = self.ml_detector.model.predict_proba(X)[0]
            
            result = {}
            for i, class_name in enumerate(self.ml_detector.class_names):
                result[class_name] = float(probabilities[i])
            
            return result
        except Exception as e:
            return {'error': str(e)}
    
    def _fuse_alerts(self, rule_alerts, ml_alert, flow_data):
        """
        Fusionne les alertes Rule-Based et ML
        
        Priorité:
        1. Hybrid (les deux détectent) → critical
        2. Rule-Based seul → high
        3. ML seul avec haute confiance → high
        4. ML seul avec confiance moyenne → medium
        """
        # Cas 1: Les deux méthodes détectent une attaque
        if rule_alerts and ml_alert:
            # Prendre l'attaque la plus sévère
            rule_attack = rule_alerts[0]['attack_type']
            ml_attack = ml_alert['attack_type']
            
            # Créer une alerte hybride
            hybrid_alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': flow_data.get('src_ip', ''),
                'dst_ip': flow_data.get('dst_ip', ''),
                'attack_type': f"{rule_attack} + {ml_attack}",
                'detection_method': 'hybrid',
                'confidence': max(rule_alerts[0]['confidence'], ml_alert['confidence']),
                'risk_level': 'critical',
                'description': f"Attaque confirmée par les deux méthodes: {rule_attack} (Rule-Based) + {ml_attack} (ML)",
                'details': {
                    'rule_based': rule_alerts[0],
                    'ml': ml_alert,
                    'confirmation': True
                }
            }
            return hybrid_alert
        
        # Cas 2: Seulement Rule-Based détecte
        if rule_alerts:
            return rule_alerts[0]
        
        # Cas 3: Seulement ML détecte
        if ml_alert:
            return ml_alert
        
        # Aucune détection
        return None
    
    def get_alerts(self):
        """Retourne toutes les alertes générées"""
        return self.alerts
    
    def get_statistics(self):
        """Retourne des statistiques sur les détections"""
        stats = {
            'total_alerts': len(self.alerts),
            'rule_based_only': 0,
            'ml_only': 0,
            'hybrid': 0,
            'by_attack_type': {},
            'by_risk_level': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }
        
        for alert in self.alerts:
            method = alert['detection_method']
            risk = alert['risk_level']
            attack_type = alert['attack_type']
            
            if method == 'hybrid':
                stats['hybrid'] += 1
            elif method == 'rule_based':
                stats['rule_based_only'] += 1
            elif method == 'ml':
                stats['ml_only'] += 1
            
            stats['by_risk_level'][risk] = stats['by_risk_level'].get(risk, 0) + 1
            stats['by_attack_type'][attack_type] = stats['by_attack_type'].get(attack_type, 0) + 1
        
        return stats
    
    def reset(self):
        """Réinitialise le détecteur"""
        self.alerts.clear()
        if self.rule_detector:
            self.rule_detector.reset()


if __name__ == "__main__":
    # Test du détecteur hybride
    print("Test du module hybrid_detector.py")
    print("=" * 50)
    
    # Importer les autres modules
    from rule_engine import RuleBasedDetector
    
    # Créer les détecteurs
    rule_detector = RuleBasedDetector()
    
    hybrid = HybridDetector()
    hybrid.set_rule_detector(rule_detector)
    # Note: ml_detector nécessite un modèle entraîné
    
    # Test Rule-Based uniquement
    print("\n[Test] Simulation d'attaque Port Scan...")
    
    for port in range(1, 120):
        flow = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'src_port': 45000,
            'dst_port': port,
            'proto': 'tcp',
            'spkts': 1,
            'rate': 10,
            # Features ML (fictives pour ce test)
            'dur': 0.1, 'sbytes': 100, 'dbytes': 200,
            'sttl': 64, 'dttl': 64, 'service': '-', 'state': 'CON'
        }
        alert = hybrid.analyze_flow(flow)
        if alert:
            print(f"✓ Alerte détectée: {alert['attack_type']}")
            print(f"  Méthode: {alert['detection_method']}")
            print(f"  Risque: {alert['risk_level']}")
            break
    
    # Statistiques
    stats = hybrid.get_statistics()
    print(f"\nStatistiques: {stats}")
    
    print("\n✓ Test hybride terminé!")
