"""
live_capture.py - Capture réseau temps réel avec pyshark/Scapy
Reconstruction de flux 5-tuple et extraction des 29 features
"""

import time
import threading
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from config import CAPTURE_TIMEOUT, PACKET_BUFFER_SIZE


class FlowTracker:
    """Suivi des flux réseau par 5-tuple"""
    
    def __init__(self):
        self.flows = {}  # flow_key → flow_data
        self.lock = threading.Lock()
        
    def _get_flow_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Crée une clé unique pour un flux (bidirectionnel)"""
        # Normaliser pour que le même flux dans les deux directions ait la même clé
        endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return f"{proto}:{endpoints[0][0]}:{endpoints[0][1]}:{endpoints[1][0]}:{endpoints[1][1]}"
    
    def update_flow(self, packet_info):
        """
        Met à jour un flux avec un nouveau paquet
        
        Args:
            packet_info: dict avec src_ip, dst_ip, src_port, dst_port, proto, size, flags
        """
        with self.lock:
            key = self._get_flow_key(
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info.get('src_port', 0),
                packet_info.get('dst_port', 0),
                packet_info['proto']
            )
            
            current_time = time.time()
            
            if key not in self.flows:
                # Nouveau flux
                self.flows[key] = {
                    'key': key,
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info['dst_ip'],
                    'src_port': packet_info.get('src_port', 0),
                    'dst_port': packet_info.get('dst_port', 0),
                    'proto': packet_info['proto'].lower(),
                    'start_time': current_time,
                    'last_seen': current_time,
                    'sbytes': 0,
                    'dbytes': 0,
                    'spkts': 0,
                    'dpkts': 0,
                    'sttl': packet_info.get('ttl', 64),
                    'dttl': 0,
                    'flags': [],
                    'service': self._detect_service(packet_info.get('dst_port', 0))
                }
            
            flow = self.flows[key]
            flow['last_seen'] = current_time
            
            # Déterminer la direction
            is_forward = (packet_info['src_ip'] == flow['src_ip'])
            
            if is_forward:
                flow['sbytes'] += packet_info.get('size', 0)
                flow['spkts'] += 1
                flow['sttl'] = packet_info.get('ttl', flow['sttl'])
            else:
                flow['dbytes'] += packet_info.get('size', 0)
                flow['dpkts'] += 1
                flow['dttl'] = packet_info.get('ttl', 64)
            
            # Suivre les flags TCP
            if 'flags' in packet_info:
                flow['flags'].append(packet_info['flags'])
    
    def _detect_service(self, port):
        """Détecte le service basé sur le port"""
        services = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'ssl', 445: 'smb', 993: 'imaps',
            995: 'pop3s', 3306: 'mysql', 3389: 'rdp', 8080: 'http'
        }
        return services.get(port, '-')
    
    def get_expired_flows(self):
        """Retourne les flux expirés (plus d'activité depuis CAPTURE_TIMEOUT)"""
        expired = []
        current_time = time.time()
        
        with self.lock:
            keys_to_remove = []
            
            for key, flow in self.flows.items():
                if current_time - flow['last_seen'] > CAPTURE_TIMEOUT:
                    # Calculer la durée
                    flow['dur'] = flow['last_seen'] - flow['start_time']
                    
                    # Calculer le rate
                    if flow['dur'] > 0:
                        flow['rate'] = (flow['spkts'] + flow['dpkts']) / flow['dur']
                    else:
                        flow['rate'] = 0
                    
                    # Déterminer l'état TCP
                    flow['state'] = self._determine_state(flow['flags'])
                    
                    # Ajouter des features par défaut pour les autres
                    self._add_default_features(flow)
                    
                    expired.append(flow)
                    keys_to_remove.append(key)
            
            # Supprimer les flux expirés
            for key in keys_to_remove:
                del self.flows[key]
        
        return expired
    
    def _determine_state(self, flags):
        """Détermine l'état de la connexion TCP"""
        if not flags:
            return 'CON'
        
        flags_set = set(flags)
        
        if 'R' in flags_set:  # RST
            return 'RST'
        elif 'F' in flags_set:  # FIN
            return 'FIN'
        elif 'S' in flags_set and 'A' not in flags_set:  # SYN seul
            return 'REQ'
        elif 'S' in flags_set and 'A' in flags_set:  # SYN-ACK
            return 'ACC'
        else:
            return 'CON'
    
    def _add_default_features(self, flow):
        """Ajoute des features par défaut pour le ML"""
        defaults = {
            'sload': 0, 'dload': 0,
            'sjit': 0, 'djit': 0,
            'tcprtt': 0, 'synack': 0, 'ackdat': 0,
            'trans_depth': 0,
            'ct_srv_src': 1, 'ct_state_ttl': 1,
            'ct_dst_ltm': 1, 'ct_src_dport_ltm': 1,
            'ct_dst_sport_ltm': 1, 'ct_dst_src_ltm': 1,
            'ct_flw_http_mthd': 0,
            'is_ftp_login': 0, 'ct_ftp_cmd': 0,
            'ct_srv_dst': 1,
            'service': flow.get('service', '-')
        }
        
        for key, value in defaults.items():
            if key not in flow:
                flow[key] = value
    
    def get_all_flows(self):
        """Retourne tous les flux actifs"""
        with self.lock:
            return list(self.flows.values())
    
    def clear(self):
        """Supprime tous les flux"""
        with self.lock:
            self.flows.clear()


class LiveCapture:
    """Capture réseau temps réel"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.flow_tracker = FlowTracker()
        self.is_capturing = False
        self.capture_thread = None
        self.packet_count = 0
        self.on_flow_complete = None  # Callback pour les flux complets
        
    def start(self, interface=None, packet_callback=None):
        """
        Démarre la capture réseau
        
        Args:
            interface: Interface réseau à utiliser
            packet_callback: Callback appelé pour chaque paquet
        """
        if self.is_capturing:
            print("⚠ La capture est déjà en cours")
            return False
        
        if interface:
            self.interface = interface
        
        self.is_capturing = True
        self.packet_count = 0
        
        def capture_thread_func():
            print(f"✓ Démarrage de la capture sur {self.interface}")
            
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda x: not self.is_capturing
                )
            except Exception as e:
                print(f"✗ Erreur de capture: {e}")
            finally:
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_thread_func, daemon=True)
        self.capture_thread.start()
        
        # Thread pour vérifier les flux expirés
        threading.Thread(target=self._check_expired_flows, daemon=True).start()
        
        return True
    
    def stop(self):
        """Arrête la capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        print("✓ Capture arrêtée")
    
    def _process_packet(self, packet):
        """Traite un paquet capturé"""
        try:
            if not self.is_capturing:
                return
            
            # Filtrer uniquement IP
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            proto = ip_layer.proto
            
            packet_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'proto': self._proto_num_to_name(proto),
                'ttl': ttl,
                'size': len(packet)
            }
            
            # TCP
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = str(tcp_layer.flags)
            
            # UDP
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
            
            # ICMP
            elif proto == 1:
                packet_info['src_port'] = 0
                packet_info['dst_port'] = 0
            
            # Mettre à jour le flux
            self.flow_tracker.update_flow(packet_info)
            self.packet_count += 1
            
        except Exception as e:
            pass  # Ignorer les paquets malformés
    
    def _proto_num_to_name(self, proto_num):
        """Convertit un numéro de protocole en nom"""
        protocols = {1: 'icmp', 6: 'tcp', 17: 'udp'}
        return protocols.get(proto_num, f'proto{proto_num}')
    
    def _check_expired_flows(self):
        """Vérifie périodiquement les flux expirés"""
        while self.is_capturing:
            time.sleep(1)  # Vérifier chaque seconde
            
            expired_flows = self.flow_tracker.get_expired_flows()
            
            for flow in expired_flows:
                if self.on_flow_complete:
                    self.on_flow_complete(flow)
    
    def get_statistics(self):
        """Retourne des statistiques de capture"""
        return {
            'is_capturing': self.is_capturing,
            'interface': self.interface,
            'packet_count': self.packet_count,
            'active_flows': len(self.flow_tracker.flows)
        }


def list_interfaces():
    """Liste les interfaces réseau disponibles"""
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        print(f"Erreur: {e}")
        return []


if __name__ == "__main__":
    # Test de la capture
    print("Test du module live_capture.py")
    print("=" * 50)
    
    # Lister les interfaces
    interfaces = list_interfaces()
    print(f"\nInterfaces disponibles: {interfaces}")
    
    if not interfaces:
        print("⚠ Aucune interface disponible")
    else:
        # Utiliser la première interface
        interface = interfaces[0]
        print(f"\nUtilisation de l'interface: {interface}")
        
        def on_flow(flow):
            print(f"\nFlux complet:")
            print(f"  {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']}")
            print(f"  Proto: {flow['proto']}, Service: {flow['service']}")
            print(f"  Paquets: {flow['spkts']}↑ {flow['dpkts']}↓")
            print(f"  Octets: {flow['sbytes']}↑ {flow['dbytes']}↓")
            print(f"  Durée: {flow['dur']:.2f}s, Rate: {flow['rate']:.1f} pkt/s")
        
        capture = LiveCapture(interface=interface)
        capture.on_flow_complete = on_flow
        
        print("\nDémarrage de la capture (Ctrl+C pour arrêter)...")
        capture.start()
        
        try:
            while capture.is_capturing:
                time.sleep(1)
                stats = capture.get_statistics()
                print(f"Packets: {stats['packet_count']}, Flux actifs: {stats['active_flows']}", end='\r')
        except KeyboardInterrupt:
            print("\n")
            capture.stop()
            print("\n✓ Test terminé!")
