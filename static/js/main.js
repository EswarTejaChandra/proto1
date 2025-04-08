document.addEventListener('DOMContentLoaded', function() {
    // Booking slot selection
    const slots = document.querySelectorAll('.machine-slot');
    slots.forEach(slot => {
        slot.addEventListener('click', function() {
            if (!this.classList.contains('booked')) {
                showBookingModal(this.dataset.slotId);
            }
        });
    });

    // Real-time availability updates
    function updateAvailability() {
        fetch('/api/availability')
            .then(response => response.json())
            .then(data => {
                data.forEach(machine => {
                    const slot = document.querySelector(`[data-machine-id="${machine.id}"]`);
                    if (slot) {
                        slot.classList.toggle('available', machine.available);
                        slot.classList.toggle('booked', !machine.available);
                    }
                });
            });
    }

    // Update availability every minute
    setInterval(updateAvailability, 60000);

    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
});

function showBookingModal(slotId) {
    // Implementation for booking modal
    const modal = new bootstrap.Modal(document.getElementById('bookingModal'));
    document.getElementById('slotIdInput').value = slotId;
    modal.show();
}

// Notification system
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show`;
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    const container = document.querySelector('.notifications-container');
    container.appendChild(notification);
    
    // Smooth scroll to show notification
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}