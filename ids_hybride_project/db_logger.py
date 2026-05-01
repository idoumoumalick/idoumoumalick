"""
db_logger.py - Insertion MySQL immédiate pour le mode LIVE
Une alerte = une insertion, pas de batch
"""

import mysql.connector
from datetime import datetime
from config import (
    MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, MYSQL_PORT
)


class DBLogger:
    """Logger pour insertion immédiate des alertes en base de données"""
    
    def __init__(self):
        self.connection = None
        self.connected = False
        
    def connect(self):
        """Établit la connexion à la base de données"""
        try:
            self.connection = mysql.connector.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=MYSQL_DB,
                port=MYSQL_PORT
            )
            self.connected = True
            print(f"✓ Connecté à MySQL: {MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}")
            return True
        except mysql.connector.Error as e:
            print(f"✗ Erreur de connexion MySQL: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Ferme la connexion à la base de données"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            self.connected = False
            print("✓ Déconnecté de MySQL")
    
    def log_alert(self, alert):
        """
        Insère immédiatement une alerte dans la table alerts
        
        Args:
            alert: dict d'alerte avec timestamp, src_ip, dst_ip, attack_type, etc.
            
        Returns:
            int: ID de l'alerte insérée ou -1 en cas d'erreur
        """
        if not self.connected:
            if not self.connect():
                return -1
        
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO alerts 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                 attack_type, detection_method, confidence, risk_level,
                 description, raw_data)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            # Préparer les valeurs
            values = (
                alert.get('timestamp', datetime.now().isoformat()),
                alert.get('src_ip', ''),
                alert.get('dst_ip', ''),
                alert.get('src_port', 0),
                alert.get('dst_port', 0),
                alert.get('protocol', alert.get('proto', '')),
                alert.get('attack_type', 'Unknown'),
                alert.get('detection_method', 'unknown'),
                alert.get('confidence', 0.0),
                alert.get('risk_level', 'low'),
                alert.get('description', ''),
                str(alert.get('details', {}))  # JSON serializable
            )
            
            cursor.execute(query, values)
            self.connection.commit()
            
            alert_id = cursor.lastrowid
            cursor.close()
            
            print(f"✓ Alerte #{alert_id} insérée: {alert.get('attack_type')}")
            return alert_id
            
        except mysql.connector.Error as e:
            print(f"✗ Erreur d'insertion d'alerte: {e}")
            return -1
        except Exception as e:
            print(f"✗ Erreur inattendue: {e}")
            return -1
    
    def log_traffic(self, flow_data, is_attack=False):
        """
        Log un flux réseau dans traffic_logs
        
        Args:
            flow_data: dict du flux
            is_attack: booléen indiquant si c'est une attaque
            
        Returns:
            int: ID du log ou -1 en cas d'erreur
        """
        if not self.connected:
            if not self.connect():
                return -1
        
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO traffic_logs
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                 duration, sbytes, dbytes, spkts, dpkts, is_attack)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            values = (
                datetime.now().isoformat(),
                flow_data.get('src_ip', ''),
                flow_data.get('dst_ip', ''),
                flow_data.get('src_port', 0),
                flow_data.get('dst_port', 0),
                flow_data.get('proto', ''),
                flow_data.get('dur', 0.0),
                flow_data.get('sbytes', 0),
                flow_data.get('dbytes', 0),
                flow_data.get('spkts', 0),
                flow_data.get('dpkts', 0),
                is_attack
            )
            
            cursor.execute(query, values)
            self.connection.commit()
            
            log_id = cursor.lastrowid
            cursor.close()
            
            return log_id
            
        except mysql.connector.Error as e:
            print(f"✗ Erreur de log de trafic: {e}")
            return -1
    
    def get_recent_alerts(self, limit=50):
        """
        Récupère les dernières alertes
        
        Args:
            limit: Nombre maximum d'alertes à retourner
            
        Returns:
            list de dicts d'alertes
        """
        if not self.connected:
            if not self.connect():
                return []
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            query = """
                SELECT * FROM alerts
                ORDER BY timestamp DESC
                LIMIT %s
            """
            
            cursor.execute(query, (limit,))
            alerts = cursor.fetchall()
            cursor.close()
            
            return alerts
            
        except mysql.connector.Error as e:
            print(f"✗ Erreur de récupération des alertes: {e}")
            return []
    
    def get_statistics(self, hours=24):
        """
        Récupère des statistiques sur les dernières heures
        
        Args:
            hours: Nombre d'heures à considérer
            
        Returns:
            dict de statistiques
        """
        if not self.connected:
            if not self.connect():
                return {}
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            
            # Total alertes
            cursor.execute("""
                SELECT COUNT(*) as total FROM alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
            """, (hours,))
            total = cursor.fetchone()['total']
            
            # Par type d'attaque
            cursor.execute("""
                SELECT attack_type, COUNT(*) as count FROM alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
                GROUP BY attack_type
                ORDER BY count DESC
            """, (hours,))
            by_type = cursor.fetchall()
            
            # Par niveau de risque
            cursor.execute("""
                SELECT risk_level, COUNT(*) as count FROM alerts
                WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
                GROUP BY risk_level
            """, (hours,))
            by_risk = cursor.fetchall()
            
            cursor.close()
            
            return {
                'total_alerts': total,
                'by_attack_type': {item['attack_type']: item['count'] for item in by_type},
                'by_risk_level': {item['risk_level']: item['count'] for item in by_risk}
            }
            
        except mysql.connector.Error as e:
            print(f"✗ Erreur de statistiques: {e}")
            return {}
    
    def clear_old_alerts(self, days=30):
        """
        Supprime les anciennes alertes
        
        Args:
            days: Nombre de jours à conserver
        """
        if not self.connected:
            if not self.connect():
                return
        
        try:
            cursor = self.connection.cursor()
            
            query = """
                DELETE FROM alerts
                WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)
            """
            
            cursor.execute(query, (days,))
            self.connection.commit()
            
            deleted = cursor.rowcount
            cursor.close()
            
            print(f"✓ {deleted} anciennes alertes supprimées")
            
        except mysql.connector.Error as e:
            print(f"✗ Erreur de nettoyage: {e}")


# Singleton global
_db_logger = None

def get_db_logger():
    """Retourne une instance singleton de DBLogger"""
    global _db_logger
    if _db_logger is None:
        _db_logger = DBLogger()
    return _db_logger


if __name__ == "__main__":
    # Test du logger
    print("Test du module db_logger.py")
    print("=" * 50)
    
    logger = DBLogger()
    
    # Tenter de connecter
    if logger.connect():
        print("\n✓ Connexion réussie")
        
        # Tester l'insertion d'une alerte
        test_alert = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'src_port': 45000,
            'dst_port': 22,
            'protocol': 'tcp',
            'attack_type': 'Port Scan',
            'detection_method': 'rule_based',
            'confidence': 0.85,
            'risk_level': 'high',
            'description': 'Test alert',
            'details': {'test': True}
        }
        
        alert_id = logger.log_alert(test_alert)
        print(f"Alerte insérée avec ID: {alert_id}")
        
        # Récupérer les récentes
        recent = logger.get_recent_alerts(limit=5)
        print(f"Dernières alertes: {len(recent)}")
        
        # Statistiques
        stats = logger.get_statistics(hours=24)
        print(f"Statistiques: {stats}")
        
        logger.disconnect()
    else:
        print("\n⚠ Impossible de se connecter à MySQL (vérifiez la configuration)")
