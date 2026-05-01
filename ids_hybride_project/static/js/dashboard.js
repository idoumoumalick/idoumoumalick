// IDS Hybride - JavaScript spécifique au dashboard

/**
 * Mettre à jour l'affichage des statistiques
 */
function updateStatsDisplay(stats) {
    if (!stats) return;
    
    const elements = {
        'total-alerts': stats.total_alerts || 0,
        'attacks-count': stats.by_attack_type ? Object.values(stats.by_attack_type).reduce((a, b) => a + b, 0) : 0,
        'critical-risk': stats.by_risk_level ? (stats.by_risk_level.critical || 0) : 0,
        'detection-rate': calculateDetectionRate(stats)
    };
    
    for (const [id, value] of Object.entries(elements)) {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = typeof value === 'number' && id === 'detection-rate' ? value : value.toLocaleString();
        }
    }
}

/**
 * Calculer le taux de détection (simulé)
 */
function calculateDetectionRate(stats) {
    // Taux de détection simulé basé sur les alertes
    const total = stats.total_alerts || 0;
    if (total === 0) return '0%';
    
    // Dans un scénario réel, ce serait (alertes confirmées / total événements) * 100
    const rate = Math.min(98.5, 85 + (total / 100));
    return rate.toFixed(1) + '%';
}

/**
 * Démarrer l'analyse du dataset
 */
async function startAnalysis() {
    const btn = document.getElementById('btn-analyze');
    const progressBar = document.getElementById('analysis-progress');
    const progressFill = document.getElementById('progress-fill');
    const statusText = document.getElementById('analysis-status');
    
    if (!btn || btn.disabled) return;
    
    btn.disabled = true;
    progressBar.style.display = 'block';
    progressFill.style.width = '0%';
    statusText.textContent = 'Démarrage de l\'analyse...';
    
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error);
        }
        
        showToast('Analyse démarrée', 'success');
        
        // Polling pour suivre la progression
        const pollInterval = setInterval(async () => {
            try {
                const statusResponse = await fetch('/analysis/status');
                const status = await statusResponse.json();
                
                progressFill.style.width = `${status.progress}%`;
                statusText.textContent = `Progression: ${status.progress}% (${status.alerts_count} alertes)`;
                
                if (!status.running) {
                    clearInterval(pollInterval);
                    btn.disabled = false;
                    statusText.textContent = `✓ Analyse terminée - ${status.alerts_count} alertes détectées`;
                    
                    // Mettre à jour les statistiques
                    if (status.statistics) {
                        updateStatsDisplay(status.statistics);
                    }
                    
                    // Recharger les alertes
                    loadRecentAlertsToTable();
                }
            } catch (error) {
                console.error('Erreur de polling:', error);
            }
        }, 1000);
        
    } catch (error) {
        btn.disabled = false;
        progressBar.style.display = 'none';
        statusText.textContent = '';
        showToast('Erreur: ' + error.message, 'error');
    }
}

/**
 * Entraîner le modèle ML
 */
async function trainModel() {
    if (!confirm('Voulez-vous vraiment entraîner le modèle? Cela peut prendre plusieurs minutes.')) {
        return;
    }
    
    const btn = document.getElementById('btn-train');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Entraînement en cours...';
    
    try {
        const response = await fetch('/train', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error);
        }
        
        showToast(data.message, 'success');
        
    } catch (error) {
        showToast('Erreur: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

/**
 * Charger les alertes récentes dans le tableau
 */
async function loadRecentAlertsToTable() {
    try {
        const response = await fetch('/api/alerts?limit=10');
        const data = await response.json();
        const alerts = data.alerts || [];
        
        const tbody = document.getElementById('alerts-table-body');
        if (!tbody) return;
        
        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6">Aucune alerte</td></tr>';
            return;
        }
        
        tbody.innerHTML = alerts.map(alert => {
            const riskClass = `risk-${alert.risk_level}`;
            const methodLabel = {
                'rule_based': 'Rule-Based',
                'ml': 'ML',
                'hybrid': 'Hybride'
            }[alert.detection_method] || alert.detection_method;
            
            return `
                <tr class="${riskClass}">
                    <td>${formatDate(alert.timestamp)}</td>
                    <td>${alert.src_ip}</td>
                    <td>${alert.dst_ip}</td>
                    <td>${alert.attack_type}</td>
                    <td>${methodLabel}</td>
                    <td><span class="badge ${riskClass}">${alert.risk_level}</span></td>
                </tr>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Erreur de chargement:', error);
    }
}

/**
 * Formater une date
 */
function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('fr-FR', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Afficher un toast notification
 */
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 2rem;
        border-radius: 8px;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#4f46e5'};
        color: white;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Initialisation au chargement de la page
document.addEventListener('DOMContentLoaded', () => {
    // Charger les statistiques initiales
    fetch('/api/statistics')
        .then(res => res.json())
        .then(stats => updateStatsDisplay(stats))
        .catch(err => console.log('Statistiques non disponibles'));
    
    // Charger les dernières alertes
    loadRecentAlertsToTable();
    
    // Auto-refresh toutes les 30 secondes
    setInterval(() => {
        fetch('/api/statistics')
            .then(res => res.json())
            .then(stats => updateStatsDisplay(stats))
            .catch(err => {});
        
        loadRecentAlertsToTable();
    }, 30000);
});
