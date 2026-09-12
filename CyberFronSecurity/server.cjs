const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 4317);
const DATA_FILE = process.env.CYBERFRON_AUTH_DATA || path.join(__dirname, 'users.json');
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const attempts = new Map();
const sessions = new Map();
const rateWindowMs = 15 * 60 * 1000;

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return []; }
}
function saveUsers(users) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2), { mode: 0o600 });
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (error, derived) => error ? reject(error) : resolve({ salt, hash: derived.toString('hex') })));
}
function safeEqual(left, right) {
  const a = Buffer.from(left, 'hex'); const b = Buffer.from(right, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function publicUser(user) { return { id: user.id, email: user.email, createdAt: user.createdAt }; }
function isRateLimited(key) {
  const now = Date.now(); const record = attempts.get(key) || { count: 0, resetAt: now + rateWindowMs };
  if (record.resetAt <= now) { record.count = 0; record.resetAt = now + rateWindowMs; }
  record.count += 1; attempts.set(key, record);
  return record.count > 8;
}
function parseBody(request) {
  return new Promise((resolve, reject) => { let body = ''; request.on('data', (chunk) => { body += chunk; if (body.length > 12_000) request.destroy(); }); request.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (error) { reject(error); } }); request.on('error', reject); });
}
function send(response, status, payload) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': process.env.AUTH_ORIGIN || 'null', 'Access-Control-Allow-Credentials': 'true', 'X-Content-Type-Options': 'nosniff' });
  response.end(JSON.stringify(payload));
}
function getToken(request) { return (request.headers.authorization || '').replace(/^Bearer\s+/i, ''); }
function getSessionUser(request, users) { const session = sessions.get(getToken(request)); if (!session || session.expiresAt < Date.now()) return null; return users.find((user) => user.id === session.userId) || null; }
const staticFiles = new Map([
  ['/', { file: 'index.html', type: 'text/html; charset=utf-8' }],
  ['/index.html', { file: 'index.html', type: 'text/html; charset=utf-8' }],
  ['/index.css', { file: 'index.css', type: 'text/css; charset=utf-8' }],
  ['/index.js', { file: 'index.js', type: 'text/javascript; charset=utf-8' }]
]);
const installerPath = path.join(__dirname, 'dist', 'CyberFronSecurity-Setup.exe');

async function handler(request, response) {
  if (request.method === 'OPTIONS') { response.writeHead(204, { 'Access-Control-Allow-Origin': process.env.AUTH_ORIGIN || 'null', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' }); return response.end(); }
  const url = new URL(request.url, `http://${request.headers.host}`); const users = loadUsers();
  try {
    const staticFile = request.method === 'GET' && staticFiles.get(url.pathname);
    if (staticFile) {
      response.writeHead(200, { 'Content-Type': staticFile.type, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
      return response.end(await fs.promises.readFile(path.join(__dirname, staticFile.file)));
    }
    if (request.method === 'GET' && url.pathname === '/dist/CyberFronSecurity-Setup.exe' && fs.existsSync(installerPath)) {
      response.writeHead(200, {
        'Content-Type': 'application/vnd.microsoft.portable-executable',
        'Content-Disposition': 'attachment; filename="CyberFronSecurity-Setup.exe"',
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
      });
      return fs.createReadStream(installerPath).pipe(response);
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/register') {
      const { email, password } = await parseBody(request); const normalizedEmail = String(email || '').trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || typeof password !== 'string' || password.length < 12) return send(response, 400, { error: 'Use a valid email and a password with at least 12 characters.' });
      if (users.some((user) => user.email === normalizedEmail)) return send(response, 409, { error: 'An account already exists for that email.' });
      const credentials = await hashPassword(password); const user = { id: crypto.randomUUID(), email: normalizedEmail, ...credentials, createdAt: new Date().toISOString() }; users.push(user); saveUsers(users);
      return send(response, 201, { user: publicUser(user), message: 'Account created. You can now sign in.' });
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/login') {
      const { email, password } = await parseBody(request); const normalizedEmail = String(email || '').trim().toLowerCase();
      if (isRateLimited(`${request.socket.remoteAddress}:${normalizedEmail}`)) return send(response, 429, { error: 'Too many attempts. Try again later.' });
      const user = users.find((candidate) => candidate.email === normalizedEmail); const credentials = user && await hashPassword(String(password || ''), user.salt); const valid = Boolean(user && credentials && safeEqual(credentials.hash, user.hash));
      if (!valid) return send(response, 401, { error: 'Email or password is incorrect.' });
      const token = crypto.randomBytes(32).toString('base64url'); sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
      return send(response, 200, { token, expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(), user: publicUser(user) });
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/logout') { sessions.delete(getToken(request)); return send(response, 200, { ok: true }); }
    if (request.method === 'GET' && url.pathname === '/api/auth/me') { const user = getSessionUser(request, users); return user ? send(response, 200, { user: publicUser(user) }) : send(response, 401, { error: 'Authentication required.' }); }
    if (request.method === 'POST' && url.pathname === '/api/auth/forgot-password') { await parseBody(request); return send(response, 200, { message: 'If an account exists, reset instructions will be sent to that address.' }); }
    send(response, 404, { error: 'Not found.' });
  } catch (error) { console.error(error); send(response, 500, { error: 'Unexpected server error.' }); }
}

if (require.main === module) http.createServer(handler).listen(PORT, '127.0.0.1', () => console.log(`CyberFronSecurity auth API listening on 127.0.0.1:${PORT}`));
module.exports = { handler, hashPassword, publicUser };
