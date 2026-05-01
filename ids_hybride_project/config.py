"""
Configuration centrale du système IDS Hybride
"""

# Configuration MySQL
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'password'  # À modifier
MYSQL_DB = 'ids_hybride'
MYSQL_PORT = 3306

# Mode de fonctionnement: "offline" ou "live"
MODE = "offline"

# Seuils Rule-Based
PORT_SCAN_THRESHOLD = 100      # Ports uniques → Port Scan
BRUTE_FORCE_THRESHOLD = 50     # Connexions → Brute Force
FLOOD_THRESHOLD = 1000         # Paquets/sec → DoS

# Configuration ML
ML_CONFIDENCE_THRESHOLD = 0.7   # Seuil minimum pour alerter
MODEL_TYPE = 'random_forest'

# Niveaux de risque
RISK_THRESHOLD_CRITICAL = 0.95
RISK_THRESHOLD_HIGH = 0.85
RISK_THRESHOLD_MEDIUM = 0.75

# Chemins des fichiers
MODEL_PATH = 'models/random_forest_model.joblib'
SCALER_PATH = 'models/scaler.joblib'
ENCODERS_PATH = 'models/label_encoders.joblib'
DATA_TRAINING_PATH = 'data/UNSW_NB15_training-set.csv'
DATA_TESTING_PATH = 'data/UNSW_NB15_testing-set.csv'

# Features attendues (29 exactement)
NUMERICAL_FEATURES = [
    'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sload', 'dload',
    'spkts', 'dpkts', 'rate', 'sjit', 'djit', 'tcprtt', 'synack',
    'ackdat', 'trans_depth', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_dst'
]

CATEGORICAL_FEATURES = ['proto', 'service', 'state']

ALL_FEATURES = NUMERICAL_FEATURES + CATEGORICAL_FEATURES

# Capture réseau LIVE
CAPTURE_TIMEOUT = 5  # Secondes d'inactivité avant expiration d'un flux
PACKET_BUFFER_SIZE = 1000  # Nombre max de paquets en mémoire

# Flask
FLASK_HOST = '0.0.0.0'
FLASK_PORT = 5000
FLASK_DEBUG = True

# Types d'attaques UNSW-NB15
ATTACK_CATEGORIES = [
    'Normal',
    'Fuzzers',
    'Analysis',
    'Backdoors',
    'DoS',
    'Exploits',
    'Generic',
    'Reconnaissance',
    'Shellcode',
    'Worms'
]
