function checkPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]/)) strength++;
    if (password.match(/[A-Z]/)) strength++;
    if (password.match(/[0-9]/)) strength++;
    return strength;
}
function validateEmail(email) {
    return /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/.test(email);
}
document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        const passwordInput = document.getElementById('password');
        const strengthIndicator = document.getElementById('passwordStrength');
        if (passwordInput) {
            passwordInput.addEventListener('input', function() {
                const strength = checkPasswordStrength(this.value);
                let text = '', className = '';
                if (this.value.length === 0) text = '';
                else if (strength <= 2) { text = 'Weak'; className = 'strength-weak'; }
                else if (strength <= 3) { text = 'Medium'; className = 'strength-medium'; }
                else { text = 'Strong'; className = 'strength-strong'; }
                strengthIndicator.textContent = text;
                strengthIndicator.className = className;
            });
        }
        registerForm.addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm_password');
            if (confirm && password !== confirm.value) {
                alert('Passwords do not match');
                e.preventDefault();
            }
        });
    }
});
function refreshCaptcha() { location.reload(); }
