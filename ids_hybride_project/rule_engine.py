"""
Moteur de détection Rule-Based
Détecte: Port Scan, Brute Force, Flood/DoS
"""

from collections import defaultdict
from datetime import datetime
from config import (
    PORT_SCAN_THRESHOLD, BRUTE_FORCE_THRESHOLD, FLOOD_THRESHOLD,
    RISK_THRESHOLD_HIGH, RISK_THRESHOLD_CRITICAL
)


class RuleBasedDetector:
    """Détection d'intrusions par règles et seuils"""
    
    def __init__(self):
        # Compteurs pour la détection
        self.port_scan_tracker = defaultdict(set)  # src_ip → set de (dst_ip, dst_port)
        self.brute_force_tracker = defaultdict(int)  # (src_ip, dst_ip, service) → count
        self.flood_tracker = defaultdict(lambda: {'count': 0, 'start_time': None})  # src_ip → info
        
        # Alertes générées
        self.alerts = []
        
    def analyze_flow(self, flow_data):
        """
        Analyse un flux réseau et détecte les attaques potentielles
        
        Args:
            flow_data: dict avec src_ip, dst_ip, src_port, dst_port, 
                       proto, spkts, dpkts, rate, service, etc.
                       
        Returns:
            list d'alertes détectées
        """
        alerts = []
        src_ip = flow_data.get('src_ip', '')
        dst_ip = flow_data.get('dst_ip', '')
        dst_port = flow_data.get('dst_port', 0)
        src_port = flow_data.get('src_port', 0)
        proto = flow_data.get('proto', '').lower()
        spkts = flow_data.get('spkts', 0)
        rate = flow_data.get('rate', 0)
        service = flow_data.get('service', '-').lower()
        
        # Détection Port Scan
        port_scan_alert = self._detect_port_scan(src_ip, dst_ip, dst_port)
        if port_scan_alert:
            alerts.append(port_scan_alert)
        
        # Détection Brute Force
        brute_force_alert = self._detect_brute_force(
            src_ip, dst_ip, dst_port, service
        )
        if brute_force_alert:
            alerts.append(brute_force_alert)
        
        # Détection Flood/DoS
        flood_alert = self._detect_flood(src_ip, rate, spkts)
        if flood_alert:
            alerts.append(flood_alert)
        
        return alerts
    
    def _detect_port_scan(self, src_ip, dst_ip, dst_port):
        """
        Détecte un scan de ports
        
        Un port scan est détecté quand une IP source contacte
        plus de PORT_SCAN_THRESHOLD ports différents sur une même destination
        """
        key = f"{src_ip}->{dst_ip}"
        self.port_scan_tracker[key].add(dst_port)
        
        unique_ports = len(self.port_scan_tracker[key])
        
        if unique_ports >= PORT_SCAN_THRESHOLD:
            # Calculer le niveau de risque
            risk_level = 'high'
            confidence = min(0.95, 0.7 + (unique_ports - PORT_SCAN_THRESHOLD) * 0.01)
            
            if unique_ports >= PORT_SCAN_THRESHOLD * 2:
                risk_level = 'critical'
                confidence = 0.98
            
            alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'attack_type': 'Port Scan',
                'detection_method': 'rule_based',
                'confidence': confidence,
                'risk_level': risk_level,
                'description': f"Scan de {unique_ports} ports détecté depuis {src_ip}",
                'details': {
                    'unique_ports': unique_ports,
                    'threshold': PORT_SCAN_THRESHOLD
                }
            }
            
            # Reset du compteur pour éviter les doublons
            self.port_scan_tracker[key] = set()
            
            return alert
        
        return None
    
    def _detect_brute_force(self, src_ip, dst_ip, dst_port, service):
        """
        Détecte une attaque par force brute
        
        Une attaque brute force est détectée quand il y a beaucoup
        de connexions vers un service d'authentification (SSH, FTP, etc.)
        """
        # Services sensibles aux attaques brute force
        sensitive_services = ['ssh', 'ftp', 'telnet', 'smtp', 'pop3', 'imap', 'rdp', 'mysql']
        
        if service.lower() not in sensitive_services:
            return None
        
        key = (src_ip, dst_ip, service)
        self.brute_force_tracker[key] += 1
        
        count = self.brute_force_tracker[key]
        
        if count >= BRUTE_FORCE_THRESHOLD:
            risk_level = 'high'
            confidence = min(0.95, 0.75 + (count - BRUTE_FORCE_THRESHOLD) * 0.005)
            
            if count >= BRUTE_FORCE_THRESHOLD * 2:
                risk_level = 'critical'
                confidence = 0.98
            
            alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'attack_type': 'Brute Force',
                'detection_method': 'rule_based',
                'confidence': confidence,
                'risk_level': risk_level,
                'description': f"Attaque par force brute détectée sur {service.upper()} ({count} tentatives)",
                'details': {
                    'service': service,
                    'attempt_count': count,
                    'threshold': BRUTE_FORCE_THRESHOLD
                }
            }
            
            # Reset partiel
            self.brute_force_tracker[key] = 0
            
            return alert
        
        return None
    
    def _detect_flood(self, src_ip, rate, spkts):
        """
        Détecte une attaque par flood/DoS
        
        Un flood est détecté quand le taux de paquets dépasse FLOOD_THRESHOLD
        """
        current_time = datetime.now()
        
        if self.flood_tracker[src_ip]['start_time'] is None:
            self.flood_tracker[src_ip]['start_time'] = current_time
        
        # Vérifier si le taux dépasse le seuil
        if rate >= FLOOD_THRESHOLD:
            self.flood_tracker[src_ip]['count'] += 1
        else:
            # Reset si le taux retombe
            elapsed = (current_time - self.flood_tracker[src_ip]['start_time']).total_seconds()
            if elapsed > 10:  # Fenêtre de 10 secondes
                self.flood_tracker[src_ip] = {'count': 0, 'start_time': current_time}
        
        count = self.flood_tracker[src_ip]['count']
        
        if count >= 3:  # 3 lectures consécutives au-dessus du seuil
            risk_level = 'high'
            confidence = min(0.95, 0.8 + (rate - FLOOD_THRESHOLD) / FLOOD_THRESHOLD * 0.1)
            
            if rate >= FLOOD_THRESHOLD * 2:
                risk_level = 'critical'
                confidence = 0.98
            
            alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'attack_type': 'Flood/DoS',
                'detection_method': 'rule_based',
                'confidence': confidence,
                'risk_level': risk_level,
                'description': f"Attaque par flood détectée ({rate:.0f} paquets/sec)",
                'details': {
                    'packet_rate': rate,
                    'threshold': FLOOD_THRESHOLD,
                    'consecutive_readings': count
                }
            }
            
            # Reset
            self.flood_tracker[src_ip] = {'count': 0, 'start_time': current_time}
            
            return alert
        
        return None
    
    def reset(self):
        """Réinitialise tous les compteurs"""
        self.port_scan_tracker.clear()
        self.brute_force_tracker.clear()
        self.flood_tracker.clear()
        self.alerts.clear()
    
    def get_statistics(self):
        """Retourne des statistiques sur les détections"""
        return {
            'port_scan_sources': len(self.port_scan_tracker),
            'brute_force_attempts': sum(self.brute_force_tracker.values()),
            'flood_sources': len([v for v in self.flood_tracker.values() if v['count'] > 0])
        }


if __name__ == "__main__":
    # Test du moteur Rule-Based
    print("Test du module rule_engine.py")
    print("=" * 50)
    
    detector = RuleBasedDetector()
    
    # Test 1: Port Scan simulé
    print("\n[Test 1] Simulation de Port Scan...")
    for port in range(1, 150):
        flow = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'src_port': 45000,
            'dst_port': port,
            'proto': 'tcp',
            'spkts': 1,
            'rate': 10
        }
        alerts = detector.analyze_flow(flow)
        if alerts:
            print(f"✓ Alerte Port Scan: {alerts[0]['description']}")
            print(f"  Niveau de risque: {alerts[0]['risk_level']}")
            print(f"  Confiance: {alerts[0]['confidence']:.2%}")
    
    # Reset pour test suivant
    detector.reset()
    
    # Test 2: Brute Force SSH
    print("\n[Test 2] Simulation de Brute Force SSH...")
    for i in range(60):
        flow = {
            'src_ip': '10.0.0.50',
            'dst_ip': '192.168.1.1',
            'src_port': 50000 + i,
            'dst_port': 22,
            'proto': 'tcp',
            'service': 'ssh',
            'spkts': 5,
            'rate': 50
        }
        alerts = detector.analyze_flow(flow)
        if alerts:
            print(f"✓ Alerte Brute Force: {alerts[0]['description']}")
            print(f"  Niveau de risque: {alerts[0]['risk_level']}")
    
    # Test 3: Flood
    print("\n[Test 3] Simulation de Flood...")
    for i in range(5):
        flow = {
            'src_ip': '172.16.0.100',
            'dst_ip': '192.168.1.1',
            'src_port': 12345,
            'dst_port': 80,
            'proto': 'tcp',
            'spkts': 2000,
            'rate': 1500
        }
        alerts = detector.analyze_flow(flow)
        if alerts:
            print(f"✓ Alerte Flood: {alerts[0]['description']}")
    
    print("\n✓ Tests Rule-Based terminés!")
