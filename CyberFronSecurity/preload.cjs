const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cyberFronApp', Object.freeze({
  getVersion: () => ipcRenderer.invoke('app-version'),
  notifyThreat: (details) => ipcRenderer.invoke('security-notify', details),
  onWebThreatBlocked: (callback) => ipcRenderer.on('web-threat-blocked', (_event, details) => callback(details)),
  onSecurityEvent: (callback) => ipcRenderer.on('security-event', (_event, details) => callback(details)),
  startScan: (options) => ipcRenderer.invoke('scanner-start', options),
  stopScan: () => ipcRenderer.invoke('scanner-stop'),
  getStoredToken: () => ipcRenderer.invoke('auth-token-get'),
  storeToken: (token) => ipcRenderer.invoke('auth-token-set', token),
  clearStoredToken: () => ipcRenderer.invoke('auth-token-clear'),
  getAuthApiBase: () => ipcRenderer.invoke('auth-api-base'),
  platform: process.platform,
  isDesktopApp: true,
  openExternal: (url) => ipcRenderer.invoke('open-external', url)
}));
