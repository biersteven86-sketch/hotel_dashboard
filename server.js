'use strict';
require('dotenv').config({ quiet: true });

const express   = require('express');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const session   = require('express-session');

const app  = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

// ===== Pfade (unverändert zur Projektstruktur) =====
const ROOT       = path.resolve(__dirname);
const publicDir  = path.join(ROOT, 'public');
const dataDir    = path.join(ROOT, 'data');
const authDir    = path.join(dataDir, 'auth');
const usersPath  = path.join(dataDir, 'users.json');
const tokensPath = path.join(authDir, 'reset.db.json');
const auditLog   = path.join(authDir, 'reset_audit.log');

// Dateien/Ordner sicherstellen (ohne Strukturänderung)
for (const d of [publicDir, dataDir, authDir]) { try { fs.mkdirSync(d, { recursive: true }); } catch {} }
function loadJSON(p, def){ try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return def; } }
function saveJSON(p, obj){ fs.writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8'); }
(function ensureStores(){
  const U = loadJSON(usersPath, { users: [] }); if (!Array.isArray(U.users)) U.users = []; saveJSON(usersPath, U);
  const T = loadJSON(tokensPath,{ tokens: [] }); if (!Array.isArray(T.tokens)) T.tokens = []; saveJSON(tokensPath, T);
})();

// ===== Passwort-Utils (kompatibel zu users.json: pbkdf2:sha256:310000) =====
function verifyPassword(password, user){
  if (!user?.passHash || !user?.passSalt) return false;
  const [ , digest='sha256', it='310000' ] = String(user.passAlgo||'').split(':');
  const test = crypto.pbkdf2Sync(password, user.passSalt, Number(it), 32, digest).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(test,'hex'), Buffer.from(user.passHash,'hex'));
}
function validatePasswordPolicy(p){
  return Boolean(p && p.length >= 10 && /[A-Z]/.test(p) && /[a-z]/.test(p) && (/\d/.test(p) || /[^A-Za-z0-9]/.test(p)));
}

// ===== Basics (Body/Session) — keine externe Strukturänderung =====
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const IDLE_MS = Number(process.env.SESSION_IDLE_MS || 5*60*1000);
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly:true, sameSite:'lax', secure:false, maxAge: IDLE_MS }
}));

// ===== Public-Assets & offene Pfade =====
const assetRE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?)$/i;
const OPEN_PATHS = new Set([
  '/', '/health',
  '/login', '/login.html',
  '/reset', '/reset.html',
  '/reset/validate', '/reset/confirm'
]);

// ===== Aktivitäts-/Timeout-Tracker (unverändert nutzbar) =====
app.use((req, res, next) => {
  const now = Date.now();
  const passive = assetRE.test(req.path) || OPEN_PATHS.has(req.path);
  if (req.session && req.session.user){
    const last = Number(req.session.lastActivity || 0);
    if (last && (now - last) > IDLE_MS){
      return req.session.destroy(() => {
        res.clearCookie('connect.sid', { httpOnly:true, sameSite:'lax', secure:false });
        return res.redirect('/login?timeout=1');
      });
    }
    if (!passive) req.session.lastActivity = now;
  }
  next();
});

// ===== Guards: blockiert direkte Seitenzugriffe ohne Login =====
function setNoStore(res){
  res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma','no-cache'); res.setHeader('Expires','0'); res.setHeader('Surrogate-Control','no-store');
}
app.use((req, res, next) => {
  if (assetRE.test(req.path)) return next();        // Assets immer durchlassen
  if (OPEN_PATHS.has(req.path)) return next();      // offene Pfade durchlassen
  if (req.path.endsWith('.html') && !/^\/(login|reset)\.html$/i.test(req.path)){
    return res.redirect('/login');                  // .html nur Login/Reset öffentlich
  }
  if (req.session && req.session.user){ setNoStore(res); return next(); }
  return res.redirect('/login');
});

// ===== Root → Login (gewünschte Reihenfolge) =====
app.get('/', (_req, res) => res.redirect('/login'));

// ===== Health =====
app.get ('/health', (_req, res) => res.type('text').send('OK'));
app.head('/health', (_req, res) => res.sendStatus(200));

// ===== Seiten ausliefern (Login/Reset öffentlich) =====
app.get ('/login',  (_req, res) => res.sendFile('login.html',  { root: publicDir }));
app.get ('/reset',  (_req, res) => res.sendFile('reset.html',  { root: publicDir }));

// ===== Reset-Flow (kompatibel, minimal) =====
app.get('/reset/validate', (req, res) => {
  const token = String(req.query.token||'').trim();
  const email = String(req.query.email||'').trim().toLowerCase();
  if (!token || !email) return res.status(400).json({ ok:false, error:'missing_parameters' });
  const db  = loadJSON(tokensPath, { tokens: [] });
  const now = Date.now();
  const ok  = (db.tokens||[]).some(t => t.email===email && t.token===token && !t.used && t.expiresAt>now);
  if (!ok) return res.status(404).json({ ok:false, error:'invalid_or_expired' });
  return res.json({ ok:true });
});

app.post('/reset', (req, res) => {
  const email = String(req.body.email||'').trim().toLowerCase();
  if (!email) return res.status(400).type('text').send('E-Mail fehlt');
  const token = Math.random().toString(36).slice(2,10);
  const now   = Date.now();
  const exp   = now + 30*60*1000;

  const db = loadJSON(tokensPath, { tokens: [] });
  db.tokens = Array.isArray(db.tokens) ? db.tokens : [];
  db.tokens = db.tokens.map(t => t.email===email ? { ...t, used:true } : t); // alte Tokens invalidieren
  db.tokens.push({ email, token, createdAt: now, expiresAt: exp, used:false });
  saveJSON(tokensPath, db);

  // E-Mail-Versand ist optional/extern konfiguriert → hier nur Erfolg melden
  return res.status(200).json({ ok:true, message:'token_created' });
});

app.post('/reset/confirm', (req, res) => {
  const token     = String(req.body.token || '').trim();
  const emailRaw  = String(req.body.email || '').trim();
  const email     = emailRaw.toLowerCase();
  const password  = String(req.body.password || '');
  const firstname = String(req.body.firstname || req.body.firstName || '').trim();
  const lastname  = String(req.body.lastname  || req.body.lastName  || '').trim();

  if (!token || !email || !password || !firstname || !lastname){
    return res.status(400).type('text').send('Pflichtfelder fehlen');
  }
  if (!validatePasswordPolicy(password)){
    return res.status(422).type('text').send('Passwort zu schwach');
  }

  const db  = loadJSON(tokensPath, { tokens: [] });
  const now = Date.now();
  const idx = (db.tokens||[]).findIndex(t => t.email===email && t.token===token && !t.used && t.expiresAt>now);
  if (idx === -1) return res.status(403).type('text').send('Token ungültig/abgelaufen');
  db.tokens[idx].used = true; saveJSON(tokensPath, db);

  const ud = loadJSON(usersPath, { users: [] });
  const uIdx = ud.users.findIndex(u => (u.email||'').toLowerCase() === email);
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256').toString('hex');
  const nowISO = new Date().toISOString();
  const username = emailRaw.split('@')[0];
  const record = { email, username, firstname, lastname, passAlgo:'pbkdf2:sha256:310000', passSalt:salt, passHash:hash };

  if (uIdx === -1) ud.users.push({ ...record, createdAt:nowISO, updatedAt:nowISO });
  else ud.users[uIdx] = { ...ud.users[uIdx], ...record, updatedAt:nowISO };
  saveJSON(usersPath, ud);

  try { fs.appendFileSync(auditLog, JSON.stringify({ ts:nowISO, email, firstname, lastname })+'\n'); } catch {}

  return res.type('text').send('Passwort gesetzt');
});

// ===== Login / Logout / After-Login =====
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const name = String(username || '').trim();
  const pass = String(password || '');

  // 1) users.json
  const ud = loadJSON(usersPath, { users: [] });
  const nameLower = name.toLowerCase();
  const user = ud.users.find(u =>
    (u.email && u.email.toLowerCase()===nameLower) ||
    (u.username && u.username.toLowerCase()===nameLower)
  );
  if (user && verifyPassword(pass, user)){
    req.session.user = name;
    req.session.lastActivity = Date.now();
    return res.redirect('/after-login');
  }

  // 2) Fallback aus .env (ADMIN/DASH)
  const { DASH_USER='', DASH_PASS='', ADMIN_USER='', ADMIN_PASS='' } = process.env;
  const ok = (name===DASH_USER && pass===DASH_PASS) || (name===ADMIN_USER && pass===ADMIN_PASS);
  if (!ok) return res.redirect('/login?err=1');

  req.session.user = name;
  req.session.lastActivity = Date.now();
  return res.redirect('/after-login');
});

app.get('/logout', (req, res) => {
  if (!req.session) return res.redirect('/login');
  req.session.destroy(() => {
    res.clearCookie('connect.sid', { httpOnly:true, sameSite:'lax', secure:false });
    return res.redirect('/login');
  });
});

app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser){ setNoStore(res); return res.redirect('/index'); }
  setNoStore(res); return res.redirect('/dashboard');
});

// ===== Geschützte Seiten =====
function requireAuth(req, res, next){
  if (req.session && req.session.user){ setNoStore(res); return next(); }
  return res.redirect('/login');
}
app.get('/index',     requireAuth, (_req, res) => res.sendFile('index.html',     { root: publicDir }));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile('dashboard.html', { root: publicDir }));

// ===== Static erst zum Schluss, ohne index-Autoload =====
app.use(express.static(publicDir, { index: false, extensions: ['html'] }));

// ===== 404 → Login =====
app.use((_req,res)=> res.status(404).sendFile('login.html',{root: publicDir}));

// ===== Start =====
app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
});
