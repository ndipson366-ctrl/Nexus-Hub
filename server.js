'use strict';
const BASE_DIR = typeof __dirname !== 'undefined' ? __dirname : process.cwd();   // __dirname does not exist once bundled as an ES module
require('./env');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { db } = require('./db');

/* ============ config ============ */
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || (process.env.PORT ? '0.0.0.0' : '127.0.0.1');
const FREE_LOGINS = 2;                                   // first N admin logins per account are automatic
const BCRYPT_COST = 12;
// How long the owner has to answer a login request (decimals allowed, e.g. 0.05 for tests). Default 24h.
const APPROVAL_TTL_MS = (Number(process.env.APPROVAL_TTL_MINUTES) || 1440) * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_PENDING_PER_ACCOUNT = 3;
const OWNER_SETUP_CODE = process.env.OWNER_SETUP_CODE || '';
const NOTIFY_URL = process.env.NOTIFY_URL || '';          // optional push (e.g. https://ntfy.sh/your-secret-topic)
let TRUST_PROXY = !!process.env.TRUST_PROXY;
// Serverless hosts (Netlify) run the app one request at a time and cannot hold a live push connection open.
let SERVERLESS = !!(process.env.SERVERLESS || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY);
const COOKIE = 'nh_session';
const STATUSES = ['Working', 'Testing', 'Down'];
const PUBLIC_DIR = path.join(BASE_DIR, 'public');

/* ============ small helpers ============ */
class HttpError extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra || {}; }
}
const now = () => Date.now();
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const newToken = () => crypto.randomBytes(32).toString('base64url');
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { /* ignore */ }
  }
  return out;
}
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
const publicUser = u => ({ id: u.id, username: u.username, role: u.role, isOwner: !!u.is_owner });

/* ============ validation ============ */
function validUsername(u) { return typeof u === 'string' && /^[A-Za-z0-9_.-]{3,32}$/.test(u); }
function validPassword(p) { return typeof p === 'string' && p.length >= 8 && Buffer.byteLength(p) <= 72; } // bcrypt reads 72 bytes
function normalizeUrl(s) {
  if (!s) return null;
  s = String(s).trim().replace(/^[<("'`\[]+|[>)"'`\].,;:!?]+$/g, '');
  if (!s || /\s/.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  try {
    const u = new URL(s);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (!u.hostname.includes('.') && u.hostname !== 'localhost') return null;
    return u.href;
  } catch (e) { return null; }
}
function cleanLogo(s) {
  s = String(s || '').trim();
  if (!s) return '';
  if (/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/i.test(s)) return s.length < 400000 ? s : '';
  return normalizeUrl(s) || '';
}
function hostTitle(url) {
  const host = new URL(url).hostname.replace(/^www\./, '');
  const parts = host.split('.');
  const label = parts.length > 2 ? parts[parts.length - 2] : parts[0];
  return label.charAt(0).toUpperCase() + label.slice(1);
}
function sanitizeLink(b) {
  b = b || {};
  const url = normalizeUrl(b.url);
  if (!url) return null;
  return {
    url,
    title: String(b.title || '').trim().slice(0, 200) || hostTitle(url),
    category: String(b.category || '').trim().slice(0, 60),
    status: STATUSES.includes(b.status) ? b.status : 'Testing',
    logo: cleanLogo(b.logo)
  };
}
const isUnique = e => /UNIQUE constraint failed/i.test(String(e && e.message)) || /CONSTRAINT_UNIQUE|CONSTRAINT_PRIMARYKEY/i.test(String(e && e.code));

/* ============ rate limiting (in memory; resets on restart) ============ */
const failures = new Map();
const signups = new Map();
function recent(map, key, windowMs) {
  const arr = (map.get(key) || []).filter(t => t > now() - windowMs);
  map.set(key, arr);
  return arr;
}
function checkLoginLimit(key) {
  if (recent(failures, key, 15 * 60 * 1000).length >= 8) throw new HttpError(429, 'Too many failed attempts. Try again in a few minutes.');
}
function recordFailure(key) { recent(failures, key, 15 * 60 * 1000).push(now()); }
function checkSignupLimit(ip) {
  const arr = recent(signups, ip, 60 * 60 * 1000);
  if (arr.length >= 10) throw new HttpError(429, 'Too many sign-ups from this address. Try again later.');
  arr.push(now());
}

/* ============ sessions ============ */
async function startSession(ctx, userId) {
  const token = newToken();
  await db.run('INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)', [sha256(token), userId, now() + SESSION_TTL_MS]);
  ctx.res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${ctx.secure ? '; Secure' : ''}`);
}
async function loadSession(ctx) {
  const token = parseCookies(ctx.req)[COOKIE];
  if (!token) return;
  const hash = sha256(token);
  const u = await db.get(`SELECT u.id, u.username, u.role, u.is_owner, u.status
                          FROM sessions s JOIN users u ON u.id = s.user_id
                          WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'active'`, [hash, now()]);
  if (u) { ctx.user = u; ctx.sessionHash = hash; }
}

/* ============ owner notifications (SSE + optional push) ============ */
const adminStreams = new Set();                   // { res, isOwner } for every open admin page
function broadcast(event, data, ownerOnly) {
  for (const s of adminStreams) {
    if (ownerOnly && !s.isOwner) continue;
    try { s.res.write(`event: ${event}\ndata: ${JSON.stringify(data || {})}\n\n`); } catch (e) { adminStreams.delete(s); }
  }
}
function pushNotify(text) {
  if (!NOTIFY_URL || typeof fetch !== 'function') return Promise.resolve();
  return fetch(NOTIFY_URL, { method: 'POST', body: text, headers: { Title: 'Nexus Hub', 'Content-Type': 'text/plain; charset=utf-8' }, signal: AbortSignal.timeout(4000) }).catch(() => {});
}
// On serverless hosts the function is frozen once the response is sent, so the push must finish first.
async function notify(text) { const p = pushNotify(text); if (SERVERLESS) await p; }
setInterval(() => broadcast('ping', {}), 20000).unref();

/* ============ expiry sweep ============ */
async function expireStale() {
  const r = await db.run("UPDATE login_attempts SET status = 'expired', decided_at = ? WHERE status IN ('pending','approved') AND expires_at <= ?", [now(), now()]);
  if (r.changes > 0) broadcast('refresh', {}, true);
  return r.changes;
}
async function sweep() {
  await expireStale();
  await db.run('DELETE FROM sessions WHERE expires_at <= ?', [now()]);
  await db.run("DELETE FROM login_attempts WHERE status != 'pending' AND created_at < ?", [now() - 7 * 24 * 3600 * 1000]);
  for (const m of [failures, signups]) for (const k of m.keys()) if (!recent(m, k, 60 * 60 * 1000).length) m.delete(k);
}
// Expiry itself is also checked on every read, so this only tidies up and nudges the owner's open page.
setInterval(() => { sweep().catch(e => console.error('sweep failed:', e.message)); }, 30000).unref();

/* ============ routing ============ */
const routes = [];
function route(method, pattern, auth, handler) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([a-z]+)/gi, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
  routes.push({ method, re, keys, auth, handler });
}

function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'Request too large.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!size) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(new HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', reject);
  });
}

async function handleApi(req, res, url) {
  const ctx = {
    req, res, url, params: {}, body: {}, user: null,
    ip: (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '',
    secure: !!req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https')
  };
  await loadSession(ctx);

  let match = null, pathMatched = false;
  for (const r of routes) {
    const m = r.re.exec(url.pathname);
    if (!m) continue;
    pathMatched = true;
    if (r.method !== req.method) continue;
    match = { r, m }; break;
  }
  if (!match) throw new HttpError(pathMatched ? 405 : 404, pathMatched ? 'Method not allowed.' : 'Not found.');
  match.r.keys.forEach((k, i) => { ctx.params[k] = decodeURIComponent(match.m[i + 1]); });

  const { auth } = match.r;
  if (auth !== 'none') {
    if (!ctx.user) throw new HttpError(401, 'Please log in.');
    if ((auth === 'admin' || auth === 'owner') && ctx.user.role !== 'admin') throw new HttpError(403, 'Admins only.');
    if (auth === 'owner' && !ctx.user.is_owner) throw new HttpError(403, 'Only the owner can do that.');
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    // Requiring a JSON content type blocks plain cross-site <form> posts (they cannot send it).
    if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Send JSON.');
    ctx.body = await readJson(req, 12 * 1024 * 1024);
  }
  const out = await match.r.handler(ctx);
  if (out !== undefined && !res.headersSent) send(res, 200, out);
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp' };
function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  let rel;
  try { rel = decodeURIComponent(url.pathname); } catch (e) { res.writeHead(400); return res.end(); }
  if (rel === '/') rel = '/index.html';
  const full = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!full.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else serveStatic(req, res, url);
  } catch (err) {
    if (res.headersSent) { try { res.end(); } catch (e) { /* ignore */ } return; }
    if (err instanceof HttpError) return send(res, err.status, Object.assign({ error: err.message }, err.extra));
    console.error(err);
    send(res, 500, { error: 'Server error.' });
  }
});

/* ============ auth routes ============ */
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', BCRYPT_COST);   // keeps timing equal for unknown usernames

route('GET', '/api/health', 'none', () => ({ ok: true }));       // for the host's health check; does not touch the database

route('GET', '/api/status', 'none', async () => {
  const owner = await db.get('SELECT 1 AS x FROM users WHERE is_owner = 1');
  return { ownerExists: !!owner, setupCodeRequired: !owner && !!OWNER_SETUP_CODE, freeLogins: FREE_LOGINS, realtime: !SERVERLESS };
});

route('GET', '/api/me', 'user', ctx => ({ user: publicUser(ctx.user) }));

route('POST', '/api/auth/signup', 'none', async ctx => {
  const { username, password, role, setupCode } = ctx.body;
  if (!validUsername(username)) throw new HttpError(400, 'Username must be 3-32 characters: letters, numbers, dot, dash or underscore.');
  if (!validPassword(password)) throw new HttpError(400, 'Password must be at least 8 characters (and at most 72 bytes).');
  if (role !== 'viewer' && role !== 'admin') throw new HttpError(400, 'Choose Viewer or Admin.');
  checkSignupLimit(ctx.ip);
  const hash = await bcrypt.hash(password, BCRYPT_COST);

  // One INSERT decides the role of the new account, so two people racing to be "first admin" cannot both become owner.
  const ownerExisted = !!(await db.get('SELECT 1 AS x FROM users WHERE is_owner = 1'));
  if (role === 'admin' && !ownerExisted && OWNER_SETUP_CODE && !safeEqual(typeof setupCode === 'string' ? setupCode : '', OWNER_SETUP_CODE)) {
    throw new HttpError(403, 'Invalid setup code.');
  }
  try {
    await db.run(`INSERT INTO users(username, password_hash, role, is_owner, status, created_at)
                  SELECT ?, ?, ?,
                         CASE WHEN ? = 'admin' AND NOT EXISTS (SELECT 1 FROM users WHERE is_owner = 1) THEN 1 ELSE 0 END,
                         CASE WHEN ? = 'admin' AND NOT EXISTS (SELECT 1 FROM users WHERE is_owner = 1) THEN 'active' ELSE 'pending' END,
                         ?`, [username, hash, role, role, role, now()]);   // owner = active, everyone else waits for approval
  } catch (e) {
    if (isUnique(e)) throw new HttpError(409, 'That username is already taken.');
    throw e;
  }
  const result = { isOwner: !!(await db.get('SELECT is_owner FROM users WHERE username = ?', [username])).is_owner };

  if (role === 'viewer') {
    broadcast('refresh');
    await notify(`New member request from "${username}". Open Nexus Hub to accept or decline.`);
    return { ok: true, status: 'pending', message: 'Account created. An admin has to accept it before you can log in.' };
  }
  if (result.isOwner) return { ok: true, status: 'active', owner: true, message: 'Owner admin account created. Log in with Admin login.' };
  broadcast('refresh', {}, true);
  await notify(`New admin account request from "${username}". Open Nexus Hub to approve or decline.`);
  return { ok: true, status: 'pending', message: 'Admin account requested. The owner has to approve it before you can log in.' };
});

// Shared credential check for both login flows. Never says which half was wrong.
async function verifyCredentials(ctx, expectedRole) {
  const { username, password } = ctx.body;
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password || password.length > 200) {
    throw new HttpError(400, 'Enter a username and password.');
  }
  const key = ctx.ip + '|' + username.toLowerCase();
  checkLoginLimit(key);
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) { recordFailure(key); throw new HttpError(401, 'Wrong username or password.'); }
  failures.delete(key);
  if (user.role !== expectedRole) {
    throw new HttpError(403, expectedRole === 'admin' ? 'That is a viewer account. Use Viewer login.' : 'That is an admin account. Use Admin login.');
  }
  const what = expectedRole === 'admin' ? 'admin account' : 'account';
  if (user.status === 'pending') throw new HttpError(403, expectedRole === 'admin' ? 'Your admin account is still waiting for the owner to approve it.' : 'Your account is still waiting for an admin to accept it.');
  if (user.status === 'declined') throw new HttpError(403, 'Your ' + what + ' request was declined.');
  return user;
}

route('POST', '/api/auth/login/viewer', 'none', async ctx => {
  const user = await verifyCredentials(ctx, 'viewer');
  await startSession(ctx, user.id);
  return { status: 'ok', user: publicUser(user) };
});

route('POST', '/api/auth/login/admin', 'none', async ctx => {
  const user = await verifyCredentials(ctx, 'admin');

  // The counter is bumped in a single conditional UPDATE, so simultaneous logins can never
  // take more than FREE_LOGINS free passes, and clearing browser data changes nothing.
  const free = (await db.run('UPDATE users SET login_count = login_count + 1 WHERE id = ? AND login_count < ?', [user.id, FREE_LOGINS])).changes === 1;
  if (free) {
    await startSession(ctx, user.id);
    const used = (await db.get('SELECT login_count FROM users WHERE id = ?', [user.id])).login_count;
    return { status: 'ok', user: publicUser(user), freeLoginsUsed: used, freeLoginsTotal: FREE_LOGINS };
  }

  await expireStale();
  const open = (await db.get("SELECT COUNT(*) AS n FROM login_attempts WHERE user_id = ? AND status = 'pending'", [user.id])).n;
  if (open >= MAX_PENDING_PER_ACCOUNT) throw new HttpError(429, 'There are already several login requests waiting for approval on this account.');

  const claimToken = newToken();
  const ua = String(ctx.req.headers['user-agent'] || '').slice(0, 200);
  const info = await db.run('INSERT INTO login_attempts(user_id, claim_hash, status, ip, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [user.id, sha256(claimToken), 'pending', ctx.ip, ua, now(), now() + APPROVAL_TTL_MS]);
  const attemptId = info.lastInsertRowid;
  broadcast('login-attempt', { id: attemptId, username: user.username, ip: ctx.ip }, true);
  await notify(`Admin login attempt for "${user.username}" from ${ctx.ip}. Open Nexus Hub to accept or decline.`);
  return {
    status: 'pending', attemptId, claimToken, expiresAt: now() + APPROVAL_TTL_MS,
    selfApproval: !!user.is_owner     // the owner approves their own extra logins from another logged-in session
  };
});

async function getAttempt(ctx) {
  const id = Number(ctx.params.id);
  const token = ctx.body && ctx.body.claimToken;
  const a = await db.get('SELECT * FROM login_attempts WHERE id = ?', [id]);
  if (!a || typeof token !== 'string' || !safeEqual(sha256(token), a.claim_hash)) throw new HttpError(404, 'Unknown login request.');
  if ((a.status === 'pending' || a.status === 'approved') && a.expires_at <= now()) {
    await db.run("UPDATE login_attempts SET status = 'expired', decided_at = ? WHERE id = ?", [now(), id]);
    a.status = 'expired';
  }
  return a;
}

// The waiting browser polls this. Approval is only turned into a session here, in the browser that asked.
route('POST', '/api/auth/attempts/:id/claim', 'none', async ctx => {
  const a = await getAttempt(ctx);
  if (a.status === 'pending') return { status: 'pending', expiresAt: a.expires_at };
  if (a.status !== 'approved') return { status: a.status };
  // 'approved' -> 'claimed' in one conditional UPDATE: only one browser can ever turn an approval into a session.
  const claimed = await db.run("UPDATE login_attempts SET status = 'claimed' WHERE id = ? AND status = 'approved'", [a.id]);
  if (claimed.changes !== 1) return { status: 'claimed' };
  await db.run('UPDATE users SET login_count = login_count + 1 WHERE id = ?', [a.user_id]);
  const user = await db.get("SELECT * FROM users WHERE id = ? AND status = 'active'", [a.user_id]);
  if (!user) return { status: 'claimed' };
  await startSession(ctx, user.id);
  return { status: 'ok', user: publicUser(user) };
});

route('POST', '/api/auth/attempts/:id/cancel', 'none', async ctx => {
  const a = await getAttempt(ctx);
  await db.run("UPDATE login_attempts SET status = 'cancelled', decided_at = ? WHERE id = ? AND status = 'pending'", [now(), a.id]);
  broadcast('refresh', {}, true);
  return { ok: true };
});

route('POST', '/api/auth/logout', 'none', async ctx => {
  if (ctx.sessionHash) await db.run('DELETE FROM sessions WHERE token_hash = ?', [ctx.sessionHash]);
  ctx.res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${ctx.secure ? '; Secure' : ''}`);
  return { ok: true };
});

/* ============ approvals and member management (admins) ============ */
async function pendingList(user) {
  await expireStale();
  const out = { logins: [], accounts: [], members: [] };
  out.members = await db.all("SELECT id, username, created_at AS createdAt FROM users WHERE role = 'viewer' AND status = 'pending' ORDER BY id");
  if (user.is_owner) {                      // admin logins and admin sign-ups are the owner's call
    out.logins = (await db.all(`SELECT a.id, u.username, u.is_owner AS isOwner, a.ip, a.user_agent AS userAgent, a.created_at AS createdAt, a.expires_at AS expiresAt
                                FROM login_attempts a JOIN users u ON u.id = a.user_id
                                WHERE a.status = 'pending' AND a.expires_at > ? ORDER BY a.id`, [now()])).map(x => ({ ...x, isOwner: !!x.isOwner }));
    out.accounts = await db.all("SELECT id, username, created_at AS createdAt FROM users WHERE role = 'admin' AND status = 'pending' ORDER BY id");
  }
  return out;
}
route('GET', '/api/admin/pending', 'admin', async ctx => pendingList(ctx.user));

route('GET', '/api/admin/events', 'admin', ctx => {
  if (SERVERLESS) throw new HttpError(404, 'Live updates are not available on this host; the page checks regularly instead.');
  const { req, res } = ctx;
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.write('retry: 3000\n\nevent: refresh\ndata: {}\n\n');
  const stream = { res, isOwner: !!ctx.user.is_owner };
  adminStreams.add(stream);
  req.on('close', () => adminStreams.delete(stream));
});

function decisionOf(ctx) {
  const d = ctx.body && ctx.body.decision;
  if (d !== 'accept' && d !== 'decline') throw new HttpError(400, 'Decision must be accept or decline.');
  return d;
}
route('POST', '/api/admin/logins/:id/decision', 'owner', async ctx => {
  const d = decisionOf(ctx);
  const r = await db.run("UPDATE login_attempts SET status = ?, decided_at = ? WHERE id = ? AND status = 'pending' AND expires_at > ?",
    [d === 'accept' ? 'approved' : 'declined', now(), Number(ctx.params.id), now()]);
  if (r.changes !== 1) throw new HttpError(409, 'That request was already handled or has expired.');
  broadcast('refresh');
  return { ok: true };
});
route('POST', '/api/admin/accounts/:id/decision', 'owner', async ctx => {
  const d = decisionOf(ctx);
  const r = await db.run("UPDATE users SET status = ? WHERE id = ? AND role = 'admin' AND status = 'pending'",
    [d === 'accept' ? 'active' : 'declined', Number(ctx.params.id)]);
  if (r.changes !== 1) throw new HttpError(409, 'That account request was already handled.');
  broadcast('refresh');
  return { ok: true };
});

// New viewer accounts: any admin can accept or decline.
route('POST', '/api/admin/members/:id/decision', 'admin', async ctx => {
  const d = decisionOf(ctx);
  const r = await db.run("UPDATE users SET status = ? WHERE id = ? AND role = 'viewer' AND status = 'pending'",
    [d === 'accept' ? 'active' : 'declined', Number(ctx.params.id)]);
  if (r.changes !== 1) throw new HttpError(409, 'That member request was already handled.');
  broadcast('refresh');
  return { ok: true };
});

route('GET', '/api/admin/members', 'admin', async () =>
  (await db.all("SELECT id, username, role, is_owner AS isOwner, status, created_at AS createdAt FROM users ORDER BY is_owner DESC, role, username COLLATE NOCASE"))
    .map(x => ({ ...x, isOwner: !!x.isOwner })));

// Promote an accepted viewer to admin. They get the same two free logins, then the approval rule.
route('POST', '/api/admin/members/:id/promote', 'admin', async ctx => {
  const r = await db.run("UPDATE users SET role = 'admin', login_count = 0 WHERE id = ? AND role = 'viewer' AND status = 'active'", [Number(ctx.params.id)]);
  if (r.changes !== 1) throw new HttpError(409, 'Only accepted viewers can be promoted.');
  broadcast('refresh');
  return { ok: true };
});

// Remove a member entirely (their sessions and login requests go with them). Only the owner can remove admins.
route('DELETE', '/api/admin/members/:id', 'admin', async ctx => {
  const id = Number(ctx.params.id);
  const target = await db.get('SELECT id, role, is_owner FROM users WHERE id = ?', [id]);
  if (!target) throw new HttpError(404, 'Member not found.');
  if (target.is_owner) throw new HttpError(403, 'The owner account cannot be removed.');
  if (target.id === ctx.user.id) throw new HttpError(400, 'You cannot remove your own account.');
  if (target.role === 'admin' && !ctx.user.is_owner) throw new HttpError(403, 'Only the owner can remove admins.');
  // children are deleted explicitly instead of relying on the database's cascade setting
  await db.batch([
    { sql: 'DELETE FROM sessions WHERE user_id = ?', args: [id] },
    { sql: 'DELETE FROM login_attempts WHERE user_id = ?', args: [id] },
    { sql: 'DELETE FROM users WHERE id = ?', args: [id] }
  ]);
  broadcast('refresh');
  return { ok: true };
});

/* ============ links ============ */
const linkCols = 'id, title, url, category, status, logo';
route('GET', '/api/links', 'user', () => db.all(`SELECT ${linkCols} FROM links ORDER BY id`));

route('POST', '/api/links', 'admin', async ctx => {
  const l = sanitizeLink(ctx.body);
  if (!l) throw new HttpError(400, 'Enter a valid http(s) URL.');
  try {
    const info = await db.run('INSERT INTO links(title, url, category, status, logo, created_at) VALUES (?, ?, ?, ?, ?, ?)', [l.title, l.url, l.category, l.status, l.logo, now()]);
    return { id: info.lastInsertRowid };
  } catch (e) { if (isUnique(e)) throw new HttpError(409, 'That link already exists.'); throw e; }
});

route('PUT', '/api/links/:id', 'admin', async ctx => {
  const l = sanitizeLink(ctx.body);
  if (!l) throw new HttpError(400, 'Enter a valid http(s) URL.');
  try {
    const r = await db.run('UPDATE links SET title = ?, url = ?, category = ?, status = ?, logo = ? WHERE id = ?', [l.title, l.url, l.category, l.status, l.logo, Number(ctx.params.id)]);
    if (!r.changes) throw new HttpError(404, 'Link not found.');
    return { ok: true };
  } catch (e) { if (isUnique(e)) throw new HttpError(409, 'Another link already uses that URL.'); throw e; }
});

route('DELETE', '/api/links/:id', 'admin', async ctx => {
  await db.run('DELETE FROM links WHERE id = ?', [Number(ctx.params.id)]);
  return { ok: true };
});

route('POST', '/api/links/bulk', 'admin', async ctx => {
  const items = ctx.body && ctx.body.items;
  if (!Array.isArray(items) || !items.length) throw new HttpError(400, 'Nothing to add.');
  if (items.length > 1000) throw new HttpError(400, 'Add at most 1000 links at a time.');
  // Work out everything in memory first, then send ONE atomic batch (a single round trip to the database).
  const byUrl = new Map((await db.all('SELECT id, url FROM links')).map(r => [r.url, r.id]));
  const out = { added: 0, replaced: 0, skipped: 0, invalid: 0 };
  const stmts = [], seen = new Set();
  for (const item of items) {
    const l = sanitizeLink(item);
    if (!l) { out.invalid++; continue; }
    if (seen.has(l.url)) { out.skipped++; continue; }          // same link twice in one request
    seen.add(l.url);
    const existingId = byUrl.get(l.url);
    if (existingId !== undefined) {
      if (!(item && item.replaceExisting)) { out.skipped++; continue; }
      stmts.push({ sql: 'DELETE FROM links WHERE id = ?', args: [existingId] });
      out.replaced++;
    }
    stmts.push({ sql: 'INSERT INTO links(title, url, category, status, logo, created_at) VALUES (?, ?, ?, ?, ?, ?)', args: [l.title, l.url, l.category, l.status, l.logo, now()] });
    out.added++;
  }
  if (stmts.length) {
    try { await db.batch(stmts); }
    catch (e) { if (isUnique(e)) throw new HttpError(409, 'The link list changed while adding. Please try again.'); throw e; }
  }
  return out;
});

/* ============ start ============ */
async function start() {
  await db.init();
  await new Promise(resolve => server.listen(PORT, HOST, resolve));
  console.log(`Nexus Hub running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}  (database: ${db.name})`);
  if (!(await db.get('SELECT 1 AS x FROM users WHERE is_owner = 1'))) {
    console.log('No owner yet: the first person to sign up as Admin becomes the owner.' + (OWNER_SETUP_CODE ? ' (a setup code is required)' : ''));
  }
}
// Used by the Netlify function: the same HTTP server, listening on a private local port inside the function.
let ephemeral = null;
function listenEphemeral() {
  if (!ephemeral) {
    ephemeral = (async () => {
      await db.init();
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      sweep().catch(() => {});                       // tidy expired sessions/requests once per cold start
      return server.address().port;
    })();
    ephemeral.catch(() => { ephemeral = null; });    // allow a retry if the first start failed (e.g. database unreachable)
  }
  return ephemeral;
}
function configure(opts) {
  if (opts && opts.serverless) { SERVERLESS = true; TRUST_PROXY = true; }
}

if (require.main === module) start().catch(e => { console.error('Could not start:', e); process.exit(1); });
module.exports = { server, start, listenEphemeral, configure };
