// ============================================================
// Signaller Web — shared client logic (fresh rewrite)
// ============================================================

function escHtml(s) {
    if (s === null || s === undefined) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}
function fmtCase(c) { return c ? String(c).replace(/^SYR-/, '') : c; }

function getSession() { return null; } // server-side sessions now

async function api(path, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    // CSRF token from cookie
    const m = document.cookie.match(/csrftoken=([^;]+)/);
    if (m) opts.headers['X-CSRFToken'] = decodeURIComponent(m[1]);
    if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) {
        const err = (data && (data.error || data.detail)) || res.statusText;
        throw new Error(err);
    }
    return data;
}

let authReady = (async () => {
    if (window.location.pathname.includes('login')) return null;
    try {
        const me = await api('/api/me');
        if (!me.authenticated) { window.location.href = '/login'; return null; }
        if (me.is_locked || me.must_change_password) { window.location.href = '/login'; return null; }
        currentUser = me;
        // show admin button if admin
        return me;
    } catch (e) {
        window.location.href = '/login';
        return null;
    }
})();

async function requireAuth() {
    if (currentUser) return currentUser;
    const me = await authReady;
    return me;
}

async function requireAdmin() {
    const u = await requireAuth();
    if (!u || u.role !== 'admin') { window.location.href = '/login'; return null; }
    return u;
}

async function logout() {
    try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
    window.location.href = '/login';
}

// ---------- GDPR modal ----------
function ensureGdprModal() {
    if (document.getElementById('gdpr-modal-overlay')) return;
    const div = document.createElement('div');
    div.id = 'gdpr-modal-overlay';
    div.innerHTML = `
<div class="gdpr-modal-overlay" id="gdpr-modal-inner">
  <div class="gdpr-modal-box">
    <div class="gdpr-modal-header">⚠️⚠️⚠️ DATA PROTECTION WARNING ⚠️⚠️⚠️</div>
    <div class="gdpr-modal-body">
      <p><strong>This file contains personal data protected under UK GDPR.</strong></p>
      <p>By downloading, you acknowledge and accept that:</p>
      <ul>
        <li>You are <strong>personally responsible</strong> under UK GDPR for the secure handling of this data once downloaded</li>
        <li>You must <strong>store it securely</strong> and <strong>delete it when no longer needed</strong></li>
        <li>You must <strong>not share it</strong> with unauthorised persons or post it anywhere publicly</li>
        <li>You must <strong>not download on school, college, or public devices</strong></li>
        <li>If this data is lost, stolen, or shared improperly, it constitutes a <strong>GDPR breach</strong></li>
        <li>Downloading on a personal device is permitted only if you accept full responsibility</li>
      </ul>
      <label class="gdpr-checkbox-label">
        <input type="checkbox" id="gdpr-accept-check">
        <span>I have read and understood the above. I accept full responsibility under UK GDPR.</span>
      </label>
    </div>
    <div class="gdpr-modal-actions">
      <button class="btn btn-ghost gdpr-cancel-btn" id="gdpr-cancel-btn">✗ Cancel</button>
      <button class="btn btn-success gdpr-agree-btn" id="gdpr-agree-btn" disabled>✓ I Agree — Download</button>
    </div>
  </div>
</div>`;
    document.body.appendChild(div);
    const checkbox = document.getElementById('gdpr-accept-check');
    const agreeBtn = document.getElementById('gdpr-agree-btn');
    if (checkbox && agreeBtn) checkbox.addEventListener('change', () => { agreeBtn.disabled = !checkbox.checked; });
}

function showGdprModal() {
    ensureGdprModal();
    return new Promise(resolve => {
        const overlay = document.getElementById('gdpr-modal-inner');
        if (!overlay) { resolve(false); return; }
        overlay.classList.add('open');
        const checkbox = document.getElementById('gdpr-accept-check');
        const agreeBtn = document.getElementById('gdpr-agree-btn');
        const cancelBtn = document.getElementById('gdpr-cancel-btn');
        if (checkbox) { checkbox.checked = false; agreeBtn.disabled = true; }
        function cleanup(result) {
            overlay.classList.remove('open');
            if (checkbox) checkbox.checked = false;
            if (agreeBtn) agreeBtn.disabled = true;
            cancelBtn.removeEventListener('click', onCancel);
            agreeBtn.removeEventListener('click', onAgree);
            overlay.removeEventListener('click', onOverlay);
            resolve(result);
        }
        function onOverlay(e) { if (e.target === overlay) cleanup(false); }
        function onCancel() { cleanup(false); }
        function onAgree() { cleanup(true); }
        cancelBtn.addEventListener('click', onCancel);
        agreeBtn.addEventListener('click', onAgree);
        overlay.addEventListener('click', onOverlay);
    });
}

async function confirmDataExport() {
    try { if (sessionStorage.getItem('gdpr_export_acknowledged')) return true; } catch (e) {}
    const ok = await showGdprModal();
    if (ok) { try { sessionStorage.setItem('gdpr_export_acknowledged', '1'); } catch (e) {} }
    return ok;
}

function friendlyError(error, fallback) {
    if (!error) return fallback;
    return error.message || fallback;
}

window.escHtml = escHtml;
window.fmtCase = fmtCase;
window.api = api;
window.logout = logout;
window.requireAuth = requireAuth;
window.requireAdmin = requireAdmin;
window.confirmDataExport = confirmDataExport;
window.authReady = authReady;