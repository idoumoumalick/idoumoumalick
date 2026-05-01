// IDS Hybride - JavaScript utilitaire

/**
 * Fonction utilitaire pour les requêtes fetch
 */
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Erreur inconnue');
        }
        
        return data;
    } catch (error) {
        console.error('API Request error:', error);
        throw error;
    }
}

/**
 * Formater une date ISO en format lisible
 */
function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('fr-FR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

/**
 * Afficher une notification toast
 */
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
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

/**
 * Confirmer une action
 */
function confirmAction(message) {
    return confirm(message);
}

/**
 * Démarrer l'analyse (depuis dashboard)
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
        const response = await apiRequest('/analyze', { method: 'POST' });
        showToast(response.message, 'success');
        
        // Polling pour suivre la progression
        const pollInterval = setInterval(async () => {
            const status = await apiRequest('/analysis/status');
            
            progressFill.style.width = `${status.progress}%`;
            statusText.textContent = `Progression: ${status.progress}%`;
            
            if (!status.running) {
                clearInterval(pollInterval);
                btn.disabled = false;
                statusText.textContent = `Analyse terminée - ${status.alerts_count} alertes détectées`;
                showToast('Analyse terminée avec succès!', 'success');
                
                // Mettre à jour les statistiques
                updateDashboardStats(status.statistics);
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
 * Entraîner le modèle (depuis dashboard)
 */
async function trainModel() {
    if (!confirmAction('Voulez-vous vraiment entraîner le modèle? Cela peut prendre plusieurs minutes.')) {
        return;
    }
    
    const btn = document.getElementById('btn-train');
    btn.disabled = true;
    btn.textContent = 'Entraînement en cours...';
    
    try {
        const response = await apiRequest('/train', { method: 'POST' });
        showToast(response.message, 'success');
    } catch (error) {
        showToast('Erreur: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Entraîner';
    }
}

/**
 * Mettre à jour les statistiques du dashboard
 */
function updateDashboardStats(stats) {
    if (!stats) return;
    
    const totalElement = document.getElementById('total-alerts');
    if (totalElement && stats.total_alerts !== undefined) {
        totalElement.textContent = stats.total_alerts;
    }
}

/**
 * Charger les alertes récentes
 */
async function loadRecentAlerts(limit = 10) {
    try {
        const data = await apiRequest(`/api/alerts?limit=${limit}`);
        return data.alerts || [];
    } catch (error) {
        console.error('Erreur de chargement des alertes:', error);
        return [];
    }
}

/**
 * Initialiser le dashboard au chargement
 */
document.addEventListener('DOMContentLoaded', async () => {
    // Charger les statistiques initiales
    try {
        const stats = await apiRequest('/api/statistics');
        updateDashboardStats(stats);
    } catch (error) {
        console.log('Statistiques non disponibles');
    }
    
    // Charger les dernières alertes
    const alerts = await loadRecentAlerts(5);
    const tbody = document.getElementById('alerts-table-body');
    
    if (tbody && alerts.length > 0) {
        tbody.innerHTML = alerts.map(alert => `
            <tr class="risk-${alert.risk_level}">
                <td>${formatDate(alert.timestamp)}</td>
                <td>${alert.src_ip}</td>
                <td>${alert.dst_ip}</td>
                <td>${alert.attack_type}</td>
                <td>${alert.detection_method}</td>
                <td><span class="badge risk-${alert.risk_level}">${alert.risk_level}</span></td>
            </tr>
        `).join('');
    }
});

// Ajouter les animations CSS pour les toasts
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);
