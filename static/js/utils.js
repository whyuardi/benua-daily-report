const BGE_TOKEN_KEY = 'bge_token';
const BGE_USER_KEY = 'bge_user';

function getToken() { return localStorage.getItem(BGE_TOKEN_KEY); }

function getUser() {
    try { var raw = localStorage.getItem(BGE_USER_KEY); return raw ? JSON.parse(raw) : null; }
    catch (e) { return null; }
}

function requireAuth() {
    var token = getToken();
    if (!token) { window.location.href = '/'; return null; }
    return token;
}

function logout() {
    localStorage.removeItem(BGE_TOKEN_KEY);
    localStorage.removeItem(BGE_USER_KEY);
    window.location.href = '/';
}

window.BGE_API = {
    async fetchJSON(url, options) {
        if (!options) options = {};
        var token = requireAuth();
        if (!token) throw new Error('No auth');

        var headers = { 'Authorization': 'Bearer ' + token };
        if (options.headers) Object.keys(options.headers).forEach(function(k) { headers[k] = options.headers[k]; });

        if (options.body instanceof URLSearchParams) {
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }

        var res = await fetch(url, Object.assign({}, options, { headers: headers }));

        if (res.status === 401) { logout(); throw new Error('Sesi habis, silakan login ulang'); }

        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || data.error || 'Request gagal');
        return data;
    },

    showToast: function(message, type) {
        if (!type) type = 'success';
        var container = document.getElementById('toastContainer');
        if (!container) return;
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(function() {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(function() { toast.remove(); }, 300);
        }, 3000);
    },

    showError: function(message) { this.showToast(message, 'error'); }
};

document.addEventListener('DOMContentLoaded', function() {
    var token = getToken();
    if (!token && window.location.pathname !== '/') { logout(); return; }

    // HTMX setup
    if (window.htmx) {
        htmx.config.defaultSwapStyle = 'innerHTML';
        document.body.addEventListener('htmx:configRequest', function(e) {
            e.detail.headers['Authorization'] = 'Bearer ' + token;
        });
        document.body.addEventListener('htmx:responseError', function(e) {
            if (e.detail.xhr.status === 401) logout();
        });
    }

    // User info
    var user = getUser();
    if (user) {
        var headerUser = document.getElementById('headerUser');
        if (headerUser) headerUser.innerHTML = '<strong>' + user.name + '</strong> ' + (user.division_name || '');
        document.body.classList.add('role-' + user.role);

        // Show owner-only nav items
        if (user.role === 'owner') {
            document.querySelectorAll('.owner-only').forEach(function(el) { el.style.display = ''; });
        }
    }

    // Logout
    var logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', logout);

    // Active nav
    var path = window.location.pathname;
    document.querySelectorAll('.header-nav-link').forEach(function(el) {
        if (el.getAttribute('href') === path) el.classList.add('active');
    });
});
