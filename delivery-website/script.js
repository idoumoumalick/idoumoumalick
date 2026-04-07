// Fonction de suivi de colis
function trackPackage() {
    const trackingNumber = document.getElementById('tracking-number').value;
    const resultDiv = document.getElementById('tracking-result');
    
    if (!trackingNumber.trim()) {
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = '<p style="color: #ff6b6b;">Veuillez entrer un numéro de suivi valide.</p>';
        return;
    }
    
    // Simulation de suivi de colis
    const statuses = [
        { status: 'Colis enregistré', date: '2024-01-15 08:00', location: 'Paris' },
        { status: 'En transit', date: '2024-01-15 14:30', location: 'Lyon' },
        { status: 'En cours de livraison', date: '2024-01-16 09:15', location: 'Marseille' },
        { status: 'Livré', date: '2024-01-16 11:45', location: 'Marseille' }
    ];
    
    let html = `
        <div style="text-align: left;">
            <h3 style="margin-bottom: 1rem;">Suivi du colis: ${trackingNumber}</h3>
            <div class="tracking-steps">
    `;
    
    statuses.forEach((step, index) => {
        html += `
            <div style="padding: 1rem; border-left: 3px solid ${index === statuses.length - 1 ? '#667eea' : '#e9ecef'}; margin-bottom: 1rem; background: rgba(255,255,255,0.1);">
                <strong style="color: #ff6b6b;">${step.status}</strong><br>
                <small>${step.date} - ${step.location}</small>
            </div>
        `;
    });
    
    html += `
            </div>
            <p style="margin-top: 1rem; color: #4ade80; font-weight: bold;">✓ Colis livré avec succès!</p>
        </div>
    `;
    
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = html;
}

// Gestion du formulaire de contact
document.getElementById('contactForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    alert('Merci pour votre message! Nous vous répondrons dans les plus brefs délais.');
    this.reset();
});

// Défilement fluide pour les liens de navigation
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        
        const targetId = this.getAttribute('href');
        const targetElement = document.querySelector(targetId);
        
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop - 80,
                behavior: 'smooth'
            });
        }
    });
});

// Animation des cartes de service au défilement
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver(function(entries) {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observer les cartes de service et de tarification
document.querySelectorAll('.service-card, .pricing-card').forEach(card => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(30px)';
    card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(card);
});

// Changement de style de la navbar au défilement
window.addEventListener('scroll', function() {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.background = 'rgba(102, 126, 234, 0.95)';
        navbar.style.backdropFilter = 'blur(10px)';
    } else {
        navbar.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
        navbar.style.backdropFilter = 'none';
    }
});

// Boutons "Choisir" dans la section tarifs
document.querySelectorAll('.pricing-card .btn-primary').forEach(button => {
    button.addEventListener('click', function() {
        const planName = this.closest('.pricing-card').querySelector('h3').textContent;
        alert(`Vous avez choisi le plan ${planName}. Nous allons vous rediriger vers la page de commande.`);
    });
});

// Bouton "Commander" dans la navbar
document.querySelector('.navbar .btn-primary').addEventListener('click', function() {
    alert('Redirection vers la page de commande...');
});

// Boutons dans la section hero
document.querySelectorAll('.hero .btn-primary, .hero .btn-secondary').forEach(button => {
    button.addEventListener('click', function() {
        if (this.textContent.includes('devis')) {
            document.querySelector('#contact').scrollIntoView({ behavior: 'smooth' });
        } else if (this.textContent.includes('suivre')) {
            document.querySelector('#suivi').scrollIntoView({ behavior: 'smooth' });
        }
    });
});

console.log('Site de livraison chargé avec succès! 🚚');
