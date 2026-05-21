/**
 * Main client-side interactions for Secure Login System.
 */
document.addEventListener('DOMContentLoaded', function () {

    // Password visibility toggle
    document.querySelectorAll('.toggle-password').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🙈';
            } else {
                input.type = 'password';
                btn.textContent = '👁';
            }
        });
    });

    // Login button loading animation
    const loginForm = document.querySelector('.auth-form');
    const loginBtn = document.getElementById('login-btn');

    if (loginForm && loginBtn) {
        loginForm.addEventListener('submit', function () {
            const btnText = loginBtn.querySelector('.btn-text');
            const btnLoader = loginBtn.querySelector('.btn-loader');
            if (btnText && btnLoader) {
                btnText.classList.add('hidden');
                btnLoader.classList.remove('hidden');
                loginBtn.disabled = true;
            }
        });
    }

    // Password strength indicator (register page)
    const passwordInput = document.getElementById('password');
    const strengthBar = document.getElementById('password-strength');

    if (passwordInput && strengthBar) {
        passwordInput.addEventListener('input', function () {
            const val = passwordInput.value;
            let strength = 0;

            if (val.length >= 8) strength++;
            if (/[A-Z]/.test(val)) strength++;
            if (/[a-z]/.test(val)) strength++;
            if (/\d/.test(val)) strength++;
            if (/[!@#$%^&*(),.?":{}|<>]/.test(val)) strength++;

            const colors = ['transparent', '#ff3860', '#ffdd57', '#4dabf7', '#00b894', '#00ffc8'];
            const widths = ['0%', '20%', '40%', '60%', '80%', '100%'];

            strengthBar.style.width = widths[strength];
            strengthBar.style.background = colors[strength];
        });
    }

    // Auto-dismiss flash alerts after 5 seconds
    document.querySelectorAll('.alert-cyber').forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 5000);
    });
});
