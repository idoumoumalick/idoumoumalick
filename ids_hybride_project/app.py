"""
app.py - Application Flask principale - Point d'entrée IDS Hybride
Switch de mode: MODE = "offline" | "live" (ligne 21)
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import os
from datetime import datetime
import threading

# Configuration
from config import (
    MODE, FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    DATA_TRAINING_PATH, DATA_TESTING_PATH
)

# Initialisation Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-hybride-secret-key-2024'

# Variables globes
analysis_state = {
    'running': False,
    'progress': 0,
    'alerts': [],
    'statistics': {}
}


def check_mode(required_mode):
    """Vérifie que le mode correspond"""
    if MODE != required_mode:
        return False
    return True


# ============================================================================
# ROUTES PRINCIPALES
# ============================================================================

@app.route('/')
def index():
    """Redirige vers le dashboard approprié selon le mode"""
    if MODE == 'live':
        return redirect(url_for('live.dashboard'))
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    """Page dashboard principal (mode offline)"""
    if not check_mode('offline'):
        return render_template('500.html', 
                               error="Dashboard offline non disponible en mode live"), 403
    return render_template('dashboard.html', mode=MODE)


@app.route('/alerts')
def alerts():
    """Page des alertes avec filtres"""
    return render_template('alerts.html', mode=MODE)


# ============================================================================
# ROUTES MODE OFFLINE
# ============================================================================

@app.route('/analyze', methods=['POST'])
def analyze():
    """Lance l'analyse sur le dataset CSV (mode offline uniquement)"""
    if not check_mode('offline'):
        return jsonify({'error': 'Analyse offline non disponible en mode live'}), 403
    
    global analysis_state
    
    if analysis_state['running']:
        return jsonify({'error': 'Analyse déjà en cours'}), 400
    
    # Démarrer l'analyse en arrière-plan
    analysis_state['running'] = True
    analysis_state['progress'] = 0
    analysis_state['alerts'] = []
    
    def run_analysis():
        try:
            from rule_engine import RuleBasedDetector
            from ml_supervised import MLSupervisedDetector
            from hybrid_detector import HybridDetector
            from preprocess import DataPreprocessor
            import pandas as pd
            from db_logger import get_db_logger
            
            # Charger les données
            print("Chargement du dataset...")
            df = pd.read_csv(DATA_TESTING_PATH)
            total = len(df)
            
            # Initialiser les détecteurs
            rule_detector = RuleBasedDetector()
            
            ml_detector = MLSupervisedDetector()
            try:
                ml_detector.load()
                preprocessor = DataPreprocessor()
                preprocessor.load()
                ml_detector.set_preprocessor(preprocessor)
            except FileNotFoundError:
                print("⚠ Modèle ML non chargé, utilisation de Rule-Based uniquement")
                ml_detector = None
            
            hybrid_detector = HybridDetector(rule_detector, ml_detector)
            
            # Analyser ligne par ligne (simulation)
            alerts = []
            for idx, row in df.iterrows():
                if idx % 1000 == 0:
                    analysis_state['progress'] = int((idx / total) * 100)
                
                # Créer un flux simulé
                flow_data = {
                    'src_ip': f"192.168.1.{idx % 255}",
                    'dst_ip': f"10.0.0.{idx % 100}",
                    'src_port': int(row.get('sport', 0)),
                    'dst_port': int(row.get('dsport', 0)),
                    'proto': str(row.get('proto', 'tcp')).lower(),
                    'spkts': int(row.get('spkts', 0)),
                    'rate': float(row.get('rate', 0)),
                    'service': str(row.get('service', '-')).lower(),
                    # Features ML
                    'dur': float(row.get('dur', 0)),
                    'sbytes': int(row.get('sbytes', 0)),
                    'dbytes': int(row.get('dbytes', 0)),
                    'sttl': int(row.get('sttl', 64)),
                    'dttl': int(row.get('dttl', 64)),
                    'state': str(row.get('state', 'CON')).upper()
                }
                
                # Analyser
                alert = hybrid_detector.analyze_flow(flow_data)
                if alert:
                    alerts.append(alert)
                    
                    # Logger en base
                    try:
                        logger = get_db_logger()
                        logger.log_alert(alert)
                    except:
                        pass
            
            analysis_state['alerts'] = alerts
            analysis_state['statistics'] = hybrid_detector.get_statistics()
            analysis_state['progress'] = 100
            
        except Exception as e:
            print(f"Erreur d'analyse: {e}")
            analysis_state['running'] = False
        
        analysis_state['running'] = False
    
    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Analyse démarrée'
    })


@app.route('/analysis/status', methods=['GET'])
def analysis_status():
    """Retourne l'état de l'analyse en cours"""
    return jsonify({
        'running': analysis_state['running'],
        'progress': analysis_state['progress'],
        'alerts_count': len(analysis_state['alerts']),
        'statistics': analysis_state['statistics']
    })


@app.route('/train', methods=['POST'])
def train():
    """Entraîne le modèle ML (mode offline uniquement)"""
    if not check_mode('offline'):
        return jsonify({'error': 'Entraînement non disponible en mode live'}), 403
    
    def run_training():
        try:
            from ml_supervised import train_model_from_csv
            train_model_from_csv(DATA_TRAINING_PATH)
        except Exception as e:
            print(f"Erreur d'entraînement: {e}")
    
    thread = threading.Thread(target=run_training, daemon=True)
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Entraînement démarré en arrière-plan'
    })


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """API - Retourne les alertes récentes"""
    limit = request.args.get('limit', 50, type=int)
    
    try:
        from db_logger import get_db_logger
        logger = get_db_logger()
        alerts = logger.get_recent_alerts(limit=limit)
        return jsonify({'alerts': alerts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """API - Retourne les statistiques"""
    try:
        from db_logger import get_db_logger
        logger = get_db_logger()
        stats = logger.get_statistics(hours=24)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html', error=str(error)), 500


# ============================================================================
# ENREGISTREMENT DES BLUEPRINTS
# ============================================================================

# Import et enregistrement du blueprint LIVE
if MODE == 'live':
    from routes_live import live_bp
    app.register_blueprint(live_bp)


# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("IDS HYBRIDE - Système de Détection d'Intrusion Réseau")
    print("=" * 60)
    print(f"\nMode: {MODE.upper()}")
    print(f"Serveur: http://{FLASK_HOST}:{FLASK_PORT}")
    
    if MODE == 'offline':
        print("\n📁 Mode OFFLINE - Analyse sur dataset CSV")
        print("   Routes actives: /dashboard, /alerts, /analyze, /train")
    else:
        print("\n📡 Mode LIVE - Capture réseau temps réel")
        print("   Routes actives: /live, /live/interfaces, /live/start, /live/stop")
        print("   ⚠ Nécessite des droits administrateur pour la capture")
    
    print("\n" + "=" * 60)
    print("Démarrage du serveur Flask...")
    print("=" * 60)
    
    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG,
        threaded=True
    )
