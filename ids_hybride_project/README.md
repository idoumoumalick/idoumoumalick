# 🛡️ IDS Hybride - Système de Détection d'Intrusion Réseau

## 📋 Description

Système **Hybride de Détection d'Intrusion Réseau (NIDS)** combinant deux approches complémentaires :

| Méthode | Description | Types d'attaques détectées |
|---------|-------------|---------------------------|
| **Rule-Based** | Détection par seuils et patterns prédéfinis | Port Scan, Brute Force, Flood/DoS |
| **ML Supervisé** | Random Forest entraîné sur UNSW-NB15 | 9 catégories d'attaques |
| **Hybride** | Fusion des deux méthodes | Confirmation mutuelle |

### Caractéristiques principales

- ✅ **Double détection** : Rule-Based + Machine Learning (Random Forest)
- ✅ **Mode OFFLINE** : Analyse sur dataset CSV UNSW-NB15
- ✅ **Mode LIVE** : Capture réseau temps réel (Scapy)
- ✅ **Dashboard Web** : Flask + SSE streaming temps réel
- ✅ **Base de données** : Stockage MySQL des alertes
- ✅ **29 features exactes** : Pipeline de prétraitement identique à l'entraînement

---

## 🏗️ Architecture

```
ids_hybride_project/
├── app.py                 # Application Flask — point d'entrée
├── config.py              # Configuration centrale
├── preprocess.py          # Prétraitement des données (scaler + encoders)
├── rule_engine.py         # Moteur de détection Rule-Based
├── ml_supervised.py       # Module Machine Learning Supervisé
├── hybrid_detector.py     # Intégration hybride
├── evaluate.py            # Script d'évaluation
├── database_schema.sql    # Schéma MySQL
├── requirements.txt       # Dépendances Python
│
├── live_capture.py        # Capture réseau temps réel
├── live_detector.py       # Inférence ML temps réel
├── routes_live.py         # Blueprint Flask mode LIVE
├── db_logger.py           # Insertion MySQL immédiate
│
├── data/                  # Datasets UNSW-NB15
├── models/                # Modèles entraînés (.joblib)
├── templates/             # Templates HTML
└── static/                # CSS et JavaScript
```

---

## 🚀 Installation

### 1. Prérequis

- Python 3.10+
- MySQL 8.0+
- pip

### 2. Installer les dépendances

```bash
cd ids_hybride_project
pip install -r requirements.txt
```

### 3. Configurer MySQL

```bash
mysql -u root -p < database_schema.sql
```

### 4. Configurer `config.py`

Modifier les paramètres MySQL :

```python
MYSQL_HOST     = 'localhost'
MYSQL_USER     = 'root'
MYSQL_PASSWORD = 'votre_mot_de_passe'
MYSQL_DB       = 'ids_hybride'
```

### 5. Dataset UNSW-NB15

Télécharger depuis : https://research.unsw.edu.au/projects/unsw-nb15-dataset

Placer dans `data/` :
- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

---

## 💻 Utilisation

### Mode OFFLINE (par défaut)

1. Lancer l'application :

```bash
python app.py
```

2. Accéder au dashboard : **http://localhost:5000**

3. Options disponibles :
   - **Lancer l'analyse** : Analyse le dataset de test
   - **Entraîner le modèle** : Entraîne le Random Forest

### Mode LIVE

1. Modifier `app.py` ligne 21 :

```python
MODE = "live"   # au lieu de "offline"
```

2. Lancer l'application :

```bash
# Linux nécessite sudo pour la capture réseau
sudo python app.py
```

3. Accéder à : **http://localhost:5000/live**

4. Sélectionner l'interface réseau et cliquer **Start**

---

## 🔀 Switch de mode

Dans `app.py`, ligne 21 :

```python
MODE = "offline"   # "offline" | "live"
```

| MODE | Comportement |
|------|-------------|
| `"offline"` | Analyse sur dataset CSV. Routes `/analyze` et `/train` actives. |
| `"live"` | Capture réseau temps réel. Routes `/analyze` et `/train` désactivées. |

---

## 🧠 Features du modèle (29 exactement)

### 26 features numériques
`dur`, `sbytes`, `dbytes`, `sttl`, `dttl`, `sload`, `dload`, `spkts`, `dpkts`, `rate`, `sjit`, `djit`, `tcprtt`, `synack`, `ackdat`, `trans_depth`, `ct_srv_src`, `ct_state_ttl`, `ct_dst_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`, `ct_flw_http_mthd`, `is_ftp_login`, `ct_ftp_cmd`, `ct_srv_dst`

### 3 features catégoriques
- `proto` : tcp, udp, icmp, ... (minuscules)
- `service` : http, dns, ssh, -, ... (minuscules)
- `state` : CON, FIN, REQ, RST, ... (majuscules)

---

## 📊 Dataset UNSW-NB15

### Types d'attaques (9 catégories)

1. **Fuzzers** - Données aléatoires
2. **Analysis** - Port scan, spam
3. **Backdoors** - Portes dérobées
4. **DoS** - Denial of Service
5. **Exploits** - Exploitation de vulnérabilités
6. **Generic** - Attaques génériques
7. **Reconnaissance** - Surveillance réseau
8. **Shellcode** - Code shell malveillant
9. **Worms** - Vers informatiques

---

## ⚙️ Configuration (`config.py`)

### Seuils Rule-Based

```python
PORT_SCAN_THRESHOLD   = 100    # Ports uniques → Port Scan
BRUTE_FORCE_THRESHOLD = 50     # Connexions → Brute Force
FLOOD_THRESHOLD       = 1000   # Paquets/sec → DoS
```

### ML

```python
ML_CONFIDENCE_THRESHOLD = 0.7   # Seuil minimum pour alerter
```

### Niveaux de risque

```python
RISK_THRESHOLD_CRITICAL = 0.95
RISK_THRESHOLD_HIGH     = 0.85
RISK_THRESHOLD_MEDIUM   = 0.75
```

---

## 📈 Évaluation

```bash
python evaluate.py
```

Métriques calculées :
- Accuracy
- Precision
- Recall
- F1-Score
- Matrice de confusion

---

## 🔧 Technologies

| Technologie | Usage |
|-------------|-------|
| Python 3.10+ | Langage principal |
| Flask | Framework Web + SSE |
| Scikit-learn | Random Forest + prétraitement |
| Pandas / NumPy | Traitement des données |
| MySQL | Stockage alertes |
| Scapy | Capture réseau |

---

## 🗄️ Base de données

Tables principales :

| Table | Description |
|-------|-------------|
| `alerts` | Alertes détectées |
| `traffic_logs` | Logs de trafic |
| `statistics` | Statistiques quotidiennes |
| `system_config` | Configuration système |

---

## ⚠️ Notes importantes

- Le modèle **ne doit pas être réentraîné** — utiliser les fichiers `.joblib` existants
- La capture réseau nécessite **sudo** (Linux) ou **Administrateur** (Windows)
- En mode LIVE, le dataset CSV n'est **jamais chargé**
- Les flux avec des valeurs catégorielles inconnues sont **rejetés silencieusement**
- L'interface réseau doit être sélectionnée **manuellement**

---

## 📝 Auteur

**Projet de Fin d'Études**  
Spécialité : MI (Méthodes Informatiques)

---

## 📄 License

Projet académique - Usage éducatif uniquement
