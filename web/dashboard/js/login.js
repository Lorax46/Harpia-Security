/**
 * HARPIA SECURITY — Login JS
 * Validação, toggle de senha, toast e simulação de auth
 */

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const togglePassword = document.getElementById('togglePassword');
    const btnLogin = document.getElementById('btnLogin');
    const btnText = btnLogin.querySelector('.btn-text');
    const btnLoader = btnLogin.querySelector('.btn-loader');
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toastMsg');
    const toastIcon = document.getElementById('toastIcon');

    // Toggle senha
    togglePassword.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        togglePassword.innerHTML = isPassword
            ? `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" clip-rule="evenodd"/><path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z"/></svg>`
            : `<svg viewBox="0 0 20 20" fill="currentColor"><path d="M10 12a2 2 0 100-4 2 2 0 000 4z"/><path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd"/></svg>`;
    });

    // Validação em tempo real
    emailInput.addEventListener('input', () => validateEmail());
    passwordInput.addEventListener('input', () => validatePassword());

    function validateEmail() {
        const email = emailInput.value.trim();
        const errorEl = document.getElementById('emailError');
        
        if (!email) {
            showError(emailInput, errorEl, 'Email é obrigatório');
            return false;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            showError(emailInput, errorEl, 'Email inválido');
            return false;
        }
        clearError(emailInput, errorEl);
        return true;
    }

    function validatePassword() {
        const password = passwordInput.value;
        const errorEl = document.getElementById('passwordError');
        
        if (!password) {
            showError(passwordInput, errorEl, 'Senha é obrigatória');
            return false;
        }
        if (password.length < 6) {
            showError(passwordInput, errorEl, 'Mínimo 6 caracteres');
            return false;
        }
        clearError(passwordInput, errorEl);
        return true;
    }

    function showError(input, errorEl, msg) {
        input.closest('.input-group').classList.add('has-error');
        errorEl.textContent = msg;
    }

    function clearError(input, errorEl) {
        input.closest('.input-group').classList.remove('has-error');
        errorEl.textContent = '';
    }

    // Submit
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const isEmailValid = validateEmail();
        const isPasswordValid = validatePassword();
        
        if (!isEmailValid || !isPasswordValid) return;

        // Loading state
        setLoading(true);

        // Simulação de auth (substituir por chamada real)
        try {
            await simulateAuth(emailInput.value, passwordInput.value);
            showToast('Login realizado com sucesso!', 'success');
            setTimeout(() => {
                // window.location.href = '/dashboard';
                console.log('Redirect para dashboard...');
            }, 1500);
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setLoading(false);
        }
    });

    function setLoading(loading) {
        btnLogin.disabled = loading;
        btnText.style.opacity = loading ? '0' : '1';
        btnLoader.hidden = !loading;
    }

    function simulateAuth(email, password) {
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                // Demo: aceita qualquer email/senha com 6+ chars
                if (password.length >= 6) {
                    resolve({ token: 'fake-jwt', user: email });
                } else {
                    reject(new Error('Credenciais inválidas'));
                }
            }, 1500);
        });
    }

    // Toast
    function showToast(message, type = 'info') {
        toastMsg.textContent = message;
        toastIcon.textContent = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
        toast.className = `toast ${type}`;
        toast.hidden = false;

        setTimeout(() => {
            toast.hidden = true;
        }, 4000);
    }

    // Efeito de foco inicial
    setTimeout(() => emailInput.focus(), 500);
});
