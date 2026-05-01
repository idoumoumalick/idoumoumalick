-- IDS Hybride - Schéma de base de données MySQL

CREATE DATABASE IF NOT EXISTS ids_hybride;
USE ids_hybride;

-- Table des alertes de détection d'intrusion
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(20),
    attack_type VARCHAR(50),
    detection_method ENUM('rule_based', 'ml', 'hybrid') NOT NULL,
    confidence FLOAT,
    risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT,
    raw_data JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Table des logs de trafic réseau
CREATE TABLE IF NOT EXISTS traffic_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(20),
    duration FLOAT,
    sbytes BIGINT,
    dbytes BIGINT,
    spkts INT,
    dpkts INT,
    is_attack BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Table des statistiques quotidiennes
CREATE TABLE IF NOT EXISTS statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    total_packets BIGINT DEFAULT 0,
    total_alerts INT DEFAULT 0,
    attacks_by_type JSON,
    risk_distribution JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Table de configuration système
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Index pour améliorer les performances
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX idx_alerts_dst_ip ON alerts(dst_ip);
CREATE INDEX idx_alerts_attack_type ON alerts(attack_type);
CREATE INDEX idx_traffic_timestamp ON traffic_logs(timestamp);
CREATE INDEX idx_traffic_src_ip ON traffic_logs(src_ip);

-- Insertion des configurations par défaut
INSERT INTO system_config (config_key, config_value, description) VALUES
('mode', 'offline', 'Mode de fonctionnement: offline ou live'),
('port_scan_threshold', '100', 'Seuil de détection Port Scan'),
('brute_force_threshold', '50', 'Seuil de détection Brute Force'),
('flood_threshold', '1000', 'Seuil de détection Flood/DoS'),
('ml_confidence_threshold', '0.7', 'Seuil de confiance ML minimum'),
('risk_critical', '0.95', 'Seuil de risque critique'),
('risk_high', '0.85', 'Seuil de risque élevé'),
('risk_medium', '0.75', 'Seuil de risque moyen');
