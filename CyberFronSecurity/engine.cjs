const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const DEFAULT_ROOTS = [
  path.join(os.homedir(), 'Desktop'),
  path.join(os.homedir(), 'Downloads'),
  path.join(os.homedir(), 'Documents')
];
const ignoredDirectories = new Set(['node_modules', '.git', 'AppData']);
const safeTestNames = new Set(['test-signal.cfs', 'suspicious-script-demo.js']);

async function* walkFiles(directory) {
  let entries;
  try { entries = await fs.readdir(directory, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (entry.name.startsWith('.') || ignoredDirectories.has(entry.name)) continue;
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) yield* walkFiles(entryPath);
    else if (entry.isFile()) yield entryPath;
  }
}

async function inspectFile(filePath) {
  const stats = await fs.stat(filePath);
  if (stats.size > 50 * 1024 * 1024) return { processed: true, bytesRead: 0, detection: null };
  const handle = await fs.open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(Math.min(4096, stats.size));
    await handle.read(buffer, 0, buffer.length, 0);
    const detection = safeTestNames.has(path.basename(filePath).toLowerCase()) ? {
      name: 'Simulated.Test.Signal',
      severity: 'High',
      confidence: 'high',
      reason: 'Matched an explicitly configured harmless test fixture.'
    } : null;
    return { processed: true, bytesRead: buffer.length, detection };
  } finally { await handle.close(); }
}

async function scan({ roots = DEFAULT_ROOTS, onEvent, signal } = {}) {
  let filesScanned = 0; let threatsDetected = 0;
  const emit = (event) => onEvent?.({ ...event, filesScanned, threatsDetected, occurredAt: new Date().toISOString() });
  emit({ type: 'scan-start', status: 'running', roots });
  for (const root of roots) {
    for await (const filePath of walkFiles(root)) {
      if (signal?.aborted) { emit({ type: 'scan-paused', status: 'paused' }); return { status: 'paused', filesScanned, threatsDetected }; }
      try {
        const result = await inspectFile(filePath);
        if (!result.processed) continue;
        filesScanned += 1;
        emit({ type: 'scan-progress', status: 'running', currentFile: filePath });
        if (result.detection) { threatsDetected += 1; emit({ type: 'threat-detected', status: 'isolated-pending-review', threatName: result.detection.name, severity: result.detection.severity, confidence: result.detection.confidence, location: filePath, reason: result.detection.reason }); }
      } catch (error) { emit({ type: 'scan-file-error', status: 'running', currentFile: filePath, error: error.code || 'read-failed' }); }
    }
  }
  emit({ type: 'scan-complete', status: 'complete' });
  return { status: 'complete', filesScanned, threatsDetected };
}

function startRealtimeProtection({ roots = DEFAULT_ROOTS, onEvent } = {}) {
  const watchedRoots = roots.filter((root) => {
    try { return fsSync.statSync(root).isDirectory(); } catch { return false; }
  });
  const watchers = [];
  const pending = new Map();
  let stopped = false;
  const emit = (event) => onEvent?.({ ...event, occurredAt: new Date().toISOString() });

  const inspectChangedFile = async (filePath) => {
    pending.delete(filePath);
    if (stopped) return;
    try {
      const result = await inspectFile(filePath);
      if (result.detection) {
        emit({
          type: 'threat-detected',
          status: 'isolated-pending-review',
          threatName: result.detection.name,
          severity: result.detection.severity,
          confidence: result.detection.confidence,
          location: filePath,
          reason: result.detection.reason,
          source: 'real-time-protection'
        });
      }
    } catch (error) {
      if (!['ENOENT', 'EPERM', 'EACCES'].includes(error.code)) emit({ type: 'realtime-file-error', currentFile: filePath, error: error.code || 'read-failed' });
    }
  };

  const queueInspection = (filePath) => {
    if (pending.has(filePath)) clearTimeout(pending.get(filePath));
    pending.set(filePath, setTimeout(() => inspectChangedFile(filePath), 250));
  };

  for (const root of watchedRoots) {
    try {
      const watcher = fsSync.watch(root, { recursive: true }, (_eventType, filename) => {
        if (!filename || stopped) return;
        const filePath = path.resolve(root, filename.toString());
        if (!path.basename(filePath).startsWith('.') && !ignoredDirectories.has(path.basename(path.dirname(filePath)))) queueInspection(filePath);
      });
      watchers.push(watcher);
    } catch (error) {
      emit({ type: 'realtime-root-error', root, error: error.code || 'watch-failed' });
    }
  }

  emit({ type: 'protection-status', status: 'monitoring', roots: watchedRoots });
  return {
    roots: watchedRoots,
    stop() {
      if (stopped) return;
      stopped = true;
      for (const timer of pending.values()) clearTimeout(timer);
      pending.clear();
      for (const watcher of watchers) watcher.close();
    }
  };
}

module.exports = { DEFAULT_ROOTS, inspectFile, scan, startRealtimeProtection, walkFiles };
