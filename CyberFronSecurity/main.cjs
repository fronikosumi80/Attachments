const { app, BrowserWindow, ipcMain, Notification, safeStorage, session, shell } = require('electron');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { scan, startRealtimeProtection } = require('./engine.cjs');

const APP_VERSION = app.getVersion();
const AUTH_TOKEN_FILE = path.join(app.getPath('userData'), 'auth-token.bin');
let authApiBase = null;
let activeScan = null;
let realtimeProtection = null;

function broadcastSecurityEvent(event) {
  BrowserWindow.getAllWindows().forEach((window) => window.webContents.send('security-event', event));
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1440,
    height: 960,
    minWidth: 960,
    minHeight: 680,
    backgroundColor: '#f5f8f5',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  window.once('ready-to-show', () => window.show());
  window.webContents.on('will-navigate', (event, targetUrl) => {
    const target = new URL(targetUrl);
    const evidenceBackedHosts = new Set(['phishing.test', 'malware.test']);
    if (!evidenceBackedHosts.has(target.hostname)) return;
    event.preventDefault();
    window.webContents.send('web-threat-blocked', {
      threatName: target.hostname === 'phishing.test' ? 'Simulated.Phishing.Page' : 'Simulated.Malware.Page',
      url: targetUrl,
      severity: 'High',
      reason: 'The local safe-test rule set classified this test host as unsafe.'
    });
  });
  window.loadFile(path.join(__dirname, 'index.html'));
}

app.whenReady().then(() => {
  process.env.CYBERFRON_AUTH_DATA = path.join(app.getPath('userData'), 'users.json');
  const { handler } = require('./server.cjs');
  const authServer = http.createServer(handler);
  ipcMain.handle('app-version', () => APP_VERSION);
  ipcMain.handle('scanner-start', async (_event, options = {}) => {
    if (activeScan) return { accepted: false, reason: 'A scan is already running.' };
    const controller = new AbortController(); activeScan = controller;
    try {
      const result = await scan({ roots: Array.isArray(options.roots) ? options.roots : undefined, signal: controller.signal, onEvent: (event) => BrowserWindow.getAllWindows().forEach((window) => window.webContents.send('security-event', event)) });
      return { accepted: true, result };
    } finally { activeScan = null; }
  });
  ipcMain.handle('scanner-stop', () => { if (!activeScan) return false; activeScan.abort(); return true; });
  ipcMain.handle('security-notify', (_event, details) => {
    if (!details || typeof details.title !== 'string' || typeof details.body !== 'string') return false;
    if (!Notification.isSupported()) return false;
    new Notification({ title: details.title.slice(0, 80), body: details.body.slice(0, 240), urgency: 'critical' }).show();
    return true;
  });
  ipcMain.handle('auth-api-base', () => authApiBase);
  ipcMain.handle('auth-token-get', () => {
    if (!safeStorage.isEncryptionAvailable() || !fs.existsSync(AUTH_TOKEN_FILE)) return null;
    try { return safeStorage.decryptString(fs.readFileSync(AUTH_TOKEN_FILE)); } catch { return null; }
  });
  ipcMain.handle('auth-token-set', (_event, token) => {
    if (typeof token !== 'string' || token.length < 20 || !safeStorage.isEncryptionAvailable()) return false;
    fs.mkdirSync(path.dirname(AUTH_TOKEN_FILE), { recursive: true });
    fs.writeFileSync(AUTH_TOKEN_FILE, safeStorage.encryptString(token), { mode: 0o600 });
    return true;
  });
  ipcMain.handle('auth-token-clear', () => {
    try { fs.rmSync(AUTH_TOKEN_FILE, { force: true }); } catch { /* best effort */ }
    return true;
  });
  ipcMain.handle('open-external', (_event, url) => {
    if (typeof url === 'string' && /^https:\/\//i.test(url)) return shell.openExternal(url);
    return false;
  });
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'"]
      }
    });
  });

  authServer.listen(0, '127.0.0.1', () => {
    authApiBase = `http://127.0.0.1:${authServer.address().port}`;
    createWindow();
    realtimeProtection = startRealtimeProtection({ onEvent: broadcastSecurityEvent });
    setInterval(() => {
      broadcastSecurityEvent({
        type: 'heartbeat',
        protection: realtimeProtection ? 'monitoring' : 'unavailable',
        definitionStatus: 'not-configured',
        occurredAt: new Date().toISOString()
      });
    }, 5000);
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });
});

app.on('window-all-closed', () => {
  realtimeProtection?.stop();
  if (process.platform !== 'darwin') app.quit();
});

module.exports = { APP_VERSION };
