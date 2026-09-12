(() => {
  const views = [...document.querySelectorAll('.view')];
  const navLinks = [...document.querySelectorAll('.nav-link')];
  const toast = document.querySelector('.toast');
  const isDesktop = Boolean(window.cyberFronApp?.isDesktopApp);
  let authApiBase = window.cyberFronApp?.authApiBase || (window.location.protocol === 'file:' ? 'http://127.0.0.1:4317' : window.location.origin);
  const installerUrl = './dist/CyberFronSecurity-Setup.exe';
  let authToken = null;
  let currentUser = null;
  let toastTimer;
  const securityState = { filesScanned: 0, threatsDetected: 0, lastScan: null, protection: 'active', history: [] };

  document.querySelectorAll('[data-action="download"]').forEach((link) => { link.href = installerUrl; });

  function showToast(message) {
    document.querySelector('.toast-message').textContent = message;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 2800);
  }

  function setAuthError(message, target = '[data-auth-error]') {
    document.querySelectorAll(target).forEach((node) => { node.textContent = message || ''; });
  }

  async function authRequest(path, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (authToken) headers.Authorization = `Bearer ${authToken}`;
    const response = await fetch(`${authApiBase}${path}`, { ...options, headers, credentials: 'include' });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || 'Authentication request failed.');
    return payload;
  }

  async function persistToken(token) {
    authToken = token;
    if (isDesktop && window.cyberFronApp?.storeToken) await window.cyberFronApp.storeToken(token);
    else sessionStorage.setItem('cyberfron-auth-token', token);
  }

  async function clearToken() {
    authToken = null; currentUser = null;
    if (isDesktop && window.cyberFronApp?.clearStoredToken) await window.cyberFronApp.clearStoredToken();
    sessionStorage.removeItem('cyberfron-auth-token');
  }

  function showView(viewName) {
    const target = document.querySelector(`[data-section="${viewName}"]`);
    if (!target) return;
    views.forEach((view) => view.classList.toggle('active', view === target));
    navLinks.forEach((link) => link.classList.toggle('active', link.dataset.view === viewName));
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function runScan(type) {
    const labels = { quick: 'Quick scan started', full: 'Full scan started', custom: 'Custom scan ready' };
    if (type === 'custom') { showToast(`${labels[type]} · choose a folder`); return; }
    if (!isDesktop || !window.cyberFronApp?.startScan) { showToast('A real scanner is available in the Windows application'); return; }
    const panel = document.querySelector('.scan-launcher');
    let progress = panel.querySelector('[data-live-scan]');
    if (!progress) { progress = document.createElement('div'); progress.dataset.liveScan = ''; panel.append(progress); }
    progress.innerHTML = '<div class="live-scan-head"><strong>Scanning protected areas</strong><span data-live-percent>LIVE</span></div><div class="live-progress"><b data-live-bar></b></div><p data-live-files>0 files scanned · live</p>';
    showToast(`${labels[type]} · processing real files`);
    window.cyberFronApp.startScan({ mode: type }).catch((error) => showToast(error.message || 'Unable to start scan'));
  }

  function addHistoryItem(title, detail, kind = 'success') {
    const list = document.querySelector('.activity-list');
    if (!list) return;
    const item = document.createElement('div'); item.className = 'activity-item live-history';
    item.innerHTML = `<span class="activity-symbol ${kind}">✓</span><div><strong>${title}</strong><p>${detail}</p></div><time>Just now</time>`;
    list.prepend(item); list.querySelectorAll('.live-history').forEach((entry, index) => { if (index > 2) entry.remove(); });
  }

  function dispatchSecurityEvent(event) {
    if (!['scan-progress', 'heartbeat'].includes(event.type)) securityState.history.unshift({ ...event, occurredAt: new Date().toISOString() });
    if (event.type === 'scan-complete') {
      document.querySelector('.scan-card .status-label').textContent = event.threatsDetected ? 'Review' : 'Clean';
      document.querySelector('.scan-stat strong').textContent = event.filesScanned.toLocaleString();
      document.querySelector('.scan-time').textContent = securityState.lastScan;
      addHistoryItem('Scan completed', `${event.filesScanned.toLocaleString()} files checked · ${event.threatsDetected} threats found`);
      showToast(event.threatsDetected ? 'Scan complete · review detected threats' : 'Scan complete · no new threats found');
    }
    if (event.type === 'scan-progress') {
      securityState.filesScanned = event.filesScanned;
      document.querySelector('.scan-stat strong').textContent = event.filesScanned.toLocaleString();
      const progress = document.querySelector('[data-live-scan]');
      if (progress) progress.querySelector('[data-live-files]').textContent = `${event.filesScanned.toLocaleString()} files scanned · ${event.currentFile || 'live'}`;
    }
    if (event.type === 'threat-detected') { securityState.threatsDetected += 1; document.querySelector('.stats-grid .stat-card strong').textContent = securityState.threatsDetected; addHistoryItem('Threat detected and isolated', `${event.threatName} · ${event.location}`, 'shield'); notifyThreat(event); }
    if (event.type === 'quarantine') addHistoryItem('Item moved to quarantine', `${event.threatName} · ${event.status}`, 'shield');
    if (event.type === 'web-blocked') addHistoryItem('Suspicious website blocked', event.url, 'update');
    if (event.type === 'protection-status' || event.type === 'heartbeat') {
      securityState.protection = event.status === 'monitoring' ? 'monitoring' : event.protection;
      const protectionLabel = securityState.protection === 'monitoring' ? 'Protection monitoring' : `Protection ${securityState.protection}`;
      document.querySelector('.secure-chip').innerHTML = `<span class="pulse-dot"></span>${protectionLabel}`;
      if (securityState.protection === 'monitoring') {
        document.querySelector('.protection-card h2').textContent = 'Protection active';
        document.querySelector('.protection-card .protection-foot .mono').textContent = 'MONITORING';
      }
    }
  }

  function notifyThreat(details) {
    const message = `${details.threatName} · ${details.severity} · ${details.action}`;
    showToast(message);
    if (window.cyberFronApp?.notifyThreat) window.cyberFronApp.notifyThreat({ title: details.title, body: `${details.threatName}\n${details.location}\nSeverity: ${details.severity}\n${details.action}` }).catch(() => {});
  }

  function showWebThreat(details) {
    document.querySelector('[data-web-threat-name]').textContent = details.threatName;
    showView('web-warning');
    dispatchSecurityEvent({ type: 'web-blocked', url: details.url, threatName: details.threatName });
    notifyThreat({ title: 'Suspicious Website Blocked', threatName: details.threatName, location: details.url, severity: details.severity, action: 'Go back to safety' });
  }

  function setModalMode(mode) {
    const modal = document.querySelector('[data-account-modal]');
    const title = document.querySelector('[data-auth-title]');
    const modes = { login: 'Log in', register: 'Create account', forgot: 'Reset your password' };
    modal.hidden = false; title.textContent = modes[mode] || modes.login;
    modal.querySelectorAll('[data-auth-form]').forEach((form) => { form.hidden = form.dataset.authForm !== (mode === 'login' ? 'modal-login' : mode); });
    document.querySelector('[data-auth-logout]').hidden = !currentUser;
    document.querySelector('[data-account-summary]').textContent = currentUser ? `Signed in as ${currentUser.email}` : '';
    setAuthError('', '[data-modal-error]');
  }

  function finishLogin(payload) {
    currentUser = payload.user;
    document.body.classList.remove('auth-locked');
    document.querySelector('[data-auth-gate]').hidden = true;
    document.querySelector('[data-account-modal]').hidden = true;
    showToast(`Signed in as ${currentUser.email}`);
  }

  async function handleAuthSubmit(form) {
    const formData = new FormData(form); const data = Object.fromEntries(formData.entries());
    const mode = form.dataset.authForm;
    try {
      if (mode === 'register') {
        await authRequest('/api/auth/register', { method: 'POST', body: JSON.stringify(data) });
        setModalMode('login'); setAuthError('Account created. Sign in to continue.', '[data-modal-error]'); return;
      }
      if (mode === 'forgot') {
        const result = await authRequest('/api/auth/forgot-password', { method: 'POST', body: JSON.stringify(data) });
        setAuthError(result.message, '[data-modal-error]'); return;
      }
      const result = await authRequest('/api/auth/login', { method: 'POST', body: JSON.stringify(data) });
      await persistToken(result.token); finishLogin(result);
    } catch (error) { setAuthError(error.message, mode === 'login' ? '[data-auth-error]' : '[data-modal-error]'); }
  }

  async function initializeAuth() {
    if (isDesktop && window.cyberFronApp?.getAuthApiBase) authApiBase = await window.cyberFronApp.getAuthApiBase();
    if (isDesktop && window.cyberFronApp?.getStoredToken) authToken = await window.cyberFronApp.getStoredToken();
    else authToken = sessionStorage.getItem('cyberfron-auth-token');
    if (authToken) {
      try { currentUser = (await authRequest('/api/auth/me')).user; } catch { await clearToken(); }
    }
  }

  document.addEventListener('submit', (event) => {
    const form = event.target.closest('[data-auth-form]');
    if (!form) return; event.preventDefault(); handleAuthSubmit(form);
  });
  document.addEventListener('click', async (event) => {
    const modeButton = event.target.closest('[data-auth-mode]');
    if (modeButton) { setModalMode(modeButton.dataset.authMode); return; }
    if (event.target.closest('[data-auth-close]')) { document.querySelector('[data-account-modal]').hidden = true; return; }
    if (event.target.closest('[data-action="logout"]')) { await authRequest('/api/auth/logout', { method: 'POST' }).catch(() => {}); await clearToken(); document.querySelector('[data-account-modal]').hidden = true; if (isDesktop) { document.body.classList.add('auth-locked'); document.querySelector('[data-auth-gate]').hidden = false; } else showToast('You have been logged out'); return; }
    const link = event.target.closest('[data-view], [data-view-link]');
    if (link) { event.preventDefault(); showView(link.dataset.view || link.dataset.viewLink); }
    const action = event.target.closest('[data-action]'); if (!action) return;
    const actionName = action.dataset.action;
    if (actionName === 'account') setModalMode('login');
    if (actionName === 'scan') runScan(action.dataset.scanType);
    if (actionName === 'simulate-threat') {
      dispatchSecurityEvent({ type: 'threat-detected', title: 'Threat Detected', threatName: 'Simulated.Test.Signal', location: 'Downloads/test-signal.cfs', severity: 'High', action: 'Automatically isolated in safe test mode' });
      dispatchSecurityEvent({ type: 'quarantine', threatName: 'Simulated.Test.Signal', status: 'Isolated' });
    }
    if (actionName === 'go-back') showView('dashboard');
    if (actionName === 'secure-mode') showToast('Secure browser mode is ready to review');
    if (actionName === 'notifications') showToast('No new security notifications');
    if (actionName === 'empty-quarantine') showToast('Confirmation required before removing items');
    if (actionName === 'item-menu') showToast('Review, restore, or remove this isolated item');
    if (actionName === 'learn-quarantine') showToast('Quarantine keeps items isolated from the system');
    if (actionName === 'download' || actionName === 'download-start') showToast('Download preview is ready for Windows');
  });

  document.querySelectorAll('[data-setting]').forEach((input) => input.addEventListener('change', () => showToast(`${input.checked ? 'Enabled' : 'Disabled'} · setting saved`)));
  if (window.cyberFronApp?.getVersion) window.cyberFronApp.getVersion().then((version) => document.querySelectorAll('[data-version]').forEach((node) => { node.textContent = `v${version}`; })).catch(() => {});
  if (window.cyberFronApp?.onWebThreatBlocked) window.cyberFronApp.onWebThreatBlocked(showWebThreat);
  if (window.cyberFronApp?.onSecurityEvent) window.cyberFronApp.onSecurityEvent(dispatchSecurityEvent);
  window.addEventListener('hashchange', () => showView(window.location.hash.slice(1) || 'dashboard'));
  showView(window.location.hash.slice(1) || 'dashboard');
  initializeAuth();
})();
