"""
routes_live.py - Blueprint Flask pour le mode LIVE
Endpoints:
  GET  /live/interfaces - Liste des interfaces
  GET  /live            - Dashboard live
  POST /live/start      - Démarrer la capture
  POST /live/stop       - Arrêter la capture
  GET  /live/stream     - SSE streaming temps réel
  GET  /live/status     - État actuel
"""

from flask import Blueprint, render_template, request, jsonify, Response
import json
import time
import threading
from datetime import datetime
from config import MODE
from db_logger import get_db_logger
from live_detector import get_live_detector
from live_capture import LiveCapture, list_interfaces

# Blueprint
live_bp = Blueprint('live', __name__, url_prefix='/live')

# État global
capture_state = {
    'active': False,
    'interface': None,
    'capture': None,
    'alerts_queue': [],
    'start_time': None
}


def check_mode():
    """Vérifie que le mode est 'live'"""
    if MODE != 'live':
        return False
    return True


@live_bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    """Retourne la liste des interfaces réseau disponibles"""
    if not check_mode():
        return jsonify({'error': 'Mode live non activé'}), 403
    
    interfaces = list_interfaces()
    return jsonify({
        'interfaces': interfaces,
        'count': len(interfaces)
    })


@live_bp.route('', methods=['GET'])
def dashboard():
    """Affiche le dashboard live"""
    if not check_mode():
        return render_template('500.html', 
                               error="Mode live non activé. Modifiez MODE='live' dans app.py"), 403
    return render_template('live.html')


@live_bp.route('/start', methods=['POST'])
def start_capture():
    """Démarre la capture réseau"""
    if not check_mode():
        return jsonify({'error': 'Mode live non activé'}), 403
    
    data = request.get_json() or {}
    interface = data.get('capture_id') or data.get('interface')
    
    if not interface:
        return jsonify({'error': 'Interface requise'}), 400
    
    if capture_state['active']:
        return jsonify({'error': 'Capture déjà en cours'}), 400
    
    # Initialiser le détecteur
    detector = get_live_detector()
    if not detector.load_models():
        return jsonify({'error': 'Modèles ML non chargés'}), 500
    
    # Créer la capture
    capture = LiveCapture(interface=interface)
    
    def on_flow_complete(flow):
        """Callback quand un flux est complet"""
        # Détecter avec ML
        result = detector.detect(flow)
        
        if result and result.get('is_attack', False):
            # Créer l'alerte
            alert = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': flow.get('src_ip', ''),
                'dst_ip': flow.get('dst_ip', ''),
                'src_port': flow.get('src_port', 0),
                'dst_port': flow.get('dst_port', 0),
                'protocol': flow.get('proto', ''),
                'attack_type': result.get('prediction', 'Unknown'),
                'detection_method': 'ml',
                'confidence': result.get('confidence', 0),
                'risk_level': result.get('risk_level', 'low'),
                'description': f"Attaque '{result['prediction']}' détectée (confiance: {result['confidence']:.2%})",
                'details': result
            }
            
            # Ajouter à la queue pour SSE
            capture_state['alerts_queue'].append(alert)
            
            # Limiter la taille de la queue
            if len(capture_state['alerts_queue']) > 100:
                capture_state['alerts_queue'] = capture_state['alerts_queue'][-100:]
            
            # Logger en base de données
            try:
                logger = get_db_logger()
                logger.log_alert(alert)
            except Exception as e:
                print(f"⚠ Erreur de logging: {e}")
    
    capture.on_flow_complete = on_flow_complete
    
    # Démarrer
    if capture.start(interface=interface):
        capture_state['active'] = True
        capture_state['interface'] = interface
        capture_state['capture'] = capture
        capture_state['start_time'] = datetime.now().isoformat()
        capture_state['alerts_queue'] = []
        
        return jsonify({
            'success': True,
            'message': f'Capture démarrée sur {interface}',
            'start_time': capture_state['start_time']
        })
    else:
        return jsonify({'error': 'Échec du démarrage de la capture'}), 500


@live_bp.route('/stop', methods=['POST'])
def stop_capture():
    """Arrête la capture réseau"""
    if not check_mode():
        return jsonify({'error': 'Mode live non activé'}), 403
    
    if not capture_state['active']:
        return jsonify({'error': 'Aucune capture en cours'}), 400
    
    # Arrêter la capture
    if capture_state['capture']:
        capture_state['capture'].stop()
    
    capture_state['active'] = False
    capture_state['interface'] = None
    capture_state['capture'] = None
    
    return jsonify({
        'success': True,
        'message': 'Capture arrêtée'
    })


@live_bp.route('/stream', methods=['GET'])
def stream():
    """Server-Sent Events pour le streaming temps réel"""
    if not check_mode():
        return Response("Mode live non activé", status=403)
    
    def generate():
        last_alert_count = 0
        
        while True:
            # Vérifier s'il y a de nouvelles alertes
            current_count = len(capture_state['alerts_queue'])
            
            if current_count > last_alert_count:
                # Envoyer les nouvelles alertes
                new_alerts = capture_state['alerts_queue'][last_alert_count:]
                last_alert_count = current_count
                
                for alert in new_alerts:
                    yield f"data: {json.dumps(alert)}\n\n"
            
            # Envoyer un heartbeat toutes les secondes
            stats = {
                'type': 'heartbeat',
                'timestamp': datetime.now().isoformat(),
                'active': capture_state['active'],
                'interface': capture_state['interface'],
                'alerts_count': current_count
            }
            
            if capture_state['capture']:
                cap_stats = capture_state['capture'].get_statistics()
                stats['packets'] = cap_stats.get('packet_count', 0)
                stats['active_flows'] = cap_stats.get('active_flows', 0)
            
            yield f"data: {json.dumps(stats)}\n\n"
            
            time.sleep(1)
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@live_bp.route('/status', methods=['GET'])
def get_status():
    """Retourne l'état actuel de la capture"""
    if not check_mode():
        return jsonify({'error': 'Mode live non activé'}), 403
    
    status = {
        'active': capture_state['active'],
        'interface': capture_state['interface'],
        'start_time': capture_state['start_time'],
        'alerts_count': len(capture_state['alerts_queue'])
    }
    
    if capture_state['capture']:
        cap_stats = capture_state['capture'].get_statistics()
        status['packets'] = cap_stats.get('packet_count', 0)
        status['active_flows'] = cap_stats.get('active_flows', 0)
    
    return jsonify(status)


@live_bp.route('/recent_alerts', methods=['GET'])
def get_recent_alerts():
    """Retourne les dernières alertes depuis la base de données"""
    if not check_mode():
        return jsonify({'error': 'Mode live non activé'}), 403
    
    limit = request.args.get('limit', 50, type=int)
    
    try:
        logger = get_db_logger()
        alerts = logger.get_recent_alerts(limit=limit)
        return jsonify({'alerts': alerts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    # Test standalone
    print("Test du module routes_live.py")
    print("=" * 50)
    
    # Lister les interfaces
    interfaces = list_interfaces()
    print(f"\nInterfaces disponibles: {interfaces}")
    
    print("\n✓ Module routes_live.py chargé")
