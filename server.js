// server.js
const express    = require('express');
const path       = require('path');
const fs         = require('fs');
const session    = require('express-session');
const rateLimit  = require('express-rate-limit');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');
require('dotenv').config({ quiet: true });

const app  = express();
const PORT = process.env.PORT || 3000;

// ===== Root & Verzeichnisse =====
const ROOT = process.env.HD_ROOT
  ? path.resolve(process.env.HD_ROOT)
  : path.resolve(__dirname);

const publicDir    = path.join(ROOT, 'public');
const dataDir      = path.join(ROOT, 'data');
const authDir      = path.join(dataDir, 'auth');
const usersPath    = path.join(dataDir, 'users.json');
const tokensPath   = path.join(authDir, 'reset.db.json');
const auditLogPath = path.join(authDir, 'reset_audit.log');

// Verzeichnisse sicherstellen
fs.mkdirSync(publicDir, { recursive: true });
fs.mkdirSync(authDir,   { recursive: true });
fs.mkdirSync(dataDir,   { recursive: true });

// ===== Helper: Token-DB =====
function loadTokens() {
  try {
    const raw = fs.readFileSync(tokensPath, 'utf8');
    const parsed = JSON.parse(raw);
    let tokens = parsed && parsed.tokens;
    if (!Array.isArray(tokens)) tokens = [];
    return { tokens };
  } catch {
    return { tokens: [] };
  }
}
function saveTokens(obj) {
  const out = { tokens: Array.isArray(obj.tokens) ? obj.tokens : [] };
  fs.writeFileSync(tokensPath, JSON.stringify(out, null, 2), 'utf8');
}
function purgeExpiredTokens(db) {
  const now = Date.now();
  db.tokens = db.tokens.filter(t => !t.used && t.expiresAt > now);
}

// ===== Helper: Users-DB =====
function loadUsers() {
  try {
    const raw = fs.readFileSync(usersPath, 'utf8');
    const parsed = JSON.parse(raw);
    let users = parsed && parsed.users;
    if (!Array.isArray(users)) users = [];
    return { users };
  } catch {
    return { users: [] };
  }
}
function saveUsers(obj) {
  const out = { users: Array.isArray(obj.users) ? obj.users : [] };
  fs.writeFileSync(usersPath, JSON.stringify(out, null, 2), 'utf8');
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const iterations = 310000;
  const keylen = 32;
  const digest = 'sha256';
  const hash = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
  return { algo: `pbkdf2:${digest}:${iterations}`, salt, hash };
}
function verifyPassword(password, user) {
  if (!user?.passHash || !user?.passSalt) return false;
  const parts = String(user.passAlgo || '').split(':'); // pbkdf2:sha256:310000
  const iterations = Number(parts[2] || 310000);
  const digest = parts[1] || 'sha256';
  const keylen = 32;
  const test = crypto.pbkdf2Sync(password, user.passSalt, iterations, keylen, digest).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(test, 'hex'), Buffer.from(user.passHash, 'hex'));
}

// ===== Express Basics =====
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ===== Sessions (inkl. Inaktivitäts-Timeout) =====
const IDLE_MS = Number(process.env.SESSION_IDLE_MS || 5 * 60 * 1000); // 5 Minuten

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  rolling: true,                                // Cookie bei Aktivität erneuern
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,                               // hinter TLS-Proxy ggf. true setzen
    maxAge: IDLE_MS                              // Client-Ablauf (zusätzlich zur Serverprüfung)
  }
}));

// RateLimit nur auf POST /login
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// *** Früher Root-Redirect (vor static & Guards) ***
app.use((req, res, next) => {
  if ((req.method === 'GET' || req.method === 'HEAD') && req.path === '/') {
    return res.redirect('/login');
  }
  next();
});

// Statische Assets zuerst (Index explizit aus!)
app.use(express.static(publicDir, { index: false }));

// ===== No-Store für geschützte Antworten =====
function setNoStore(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
}

// ===== Inaktivitätsprüfung (Server-seitig) =====
const assetRE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?)$/i;
const OPEN_PATHS = new Set([
  '/', '/login', '/health',
  '/reset', '/reset.html',
  '/reset/validate', '/reset/confirm',
  '/logout',
  '/session/remaining',
  '/HD-Logo.png', '/Hotel-Dashboard-Schriftzug.png', '/hotel-dashboard-bg.jpg'
]);

app.use((req, res, next) => {
  // 1) Assets & offene Pfade sind „passiv“
  const isAsset   = assetRE.test(req.path);
  const isOpen    = OPEN_PATHS.has(req.path);
  const isPassive = isAsset || isOpen || req.path === '/session/remaining';

  const now = Date.now();

  // 2) Wenn eingeloggt: Timeout prüfen
  if (req.session && req.session.user) {
    const last = Number(req.session.lastActivity || 0);
    const expired = last && (now - last) > IDLE_MS;

    if (expired) {
      return req.session.destroy(() => {
        res.clearCookie('connect.sid', { httpOnly:true, sameSite:'lax', secure:false });
        return res.redirect('/login?timeout=1');
      });
    }

    // 3) Nur „aktive“ Requests erneuern die Aktivität
    if (!isPassive) {
      req.session.lastActivity = now;
    }
  }
  return next();
});

// ===== Guards (Schutz aller nicht-öffentlichen Routen) =====
app.use((req, res, next) => {
  if (assetRE.test(req.path)) return next();
  if (OPEN_PATHS.has(req.path)) return next();
  if (req.path.startsWith('/public/')) return next();

  if (req.session && req.session.user) {
    setNoStore(res);
    return next();
  }
  return res.redirect('/login');
});

// Direkte .html Aufrufe blocken (außer login/reset)
app.use((req, res, next) => {
  if (req.path.endsWith('.html') && req.path !== '/login.html' && req.path !== '/reset.html') {
    return res.redirect('/login');
  }
  next();
});

// ===== Routen: Countdown-API =====
app.get('/session/remaining', (req, res) => {
  const now = Date.now();
  let remaining = 0;
  if (req.session && req.session.user) {
    const last = Number(req.session.lastActivity || 0);
    remaining = Math.max(0, (last ? (IDLE_MS - (now - last)) : IDLE_MS));
    setNoStore(res);
  } else {
    res.setHeader('Cache-Control', 'no-store');
  }
  res.json({ ok:true, remaining, idleMs: IDLE_MS });
});

// ===== Routen: öffentlich =====
app.get ('/login', (_req, res) => res.sendFile('login.html', { root: publicDir }));
app.head('/login', (_req, res) => res.sendStatus(200));

app.get ('/reset', (_req, res) => res.sendFile('reset.html', { root: publicDir }));
app.head('/reset', (_req, res) => res.sendStatus(200));

// Reset anstoßen: Token erzeugen + Mail
app.post('/reset', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).type('text').send('E-Mail fehlt');

    const token = Math.random().toString(36).slice(2, 10);
    const now   = Date.now();
    const exp   = now + 30 * 60 * 1000; // 30 Min

    const db = loadTokens();
    purgeExpiredTokens(db);
    db.tokens = db.tokens.filter(t => t.email !== email);
    db.tokens.push({ email, token, createdAt: now, expiresAt: exp, used: false });
    saveTokens(db);

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      tls: { rejectUnauthorized: false }
    });

    const appBase = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
    const verifyUrl = `${appBase}/reset?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;

    const info = await transporter.sendMail({
      from: `"Passwort-Service" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Passwort zurücksetzen',
      text:
`Hallo,

wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten.
Dein Code lautet: ${token}

Oder klicke:
${verifyUrl}

Der Code ist 30 Minuten gültig.
Falls du das nicht warst, kannst du diese Nachricht ignorieren.`,
      html:
`<p>Hallo,</p>
<p>wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten.</p>
<p>Dein Code lautet: <b>${token}</b></p>
<p>Oder klicke: <a href="${verifyUrl}">${verifyUrl}</a></p>
<p>Der Code ist 30&nbsp;Minuten gültig.<br>Falls du das nicht warst, kannst du diese Nachricht ignorieren.</p>`
    });

    console.log('✅ Reset-Mail verschickt:', info.messageId, '→', email);
    return res.type('text').send('Reset-Mail verschickt. Bitte Postfach prüfen.');
  } catch (err) {
    console.error('❌ Fehler /reset:', err && (err.stack || err));
    return res.status(500).type('text').send('Mailversand fehlgeschlagen');
  }
});

// Token prüfen (für UI-Vorprüfung)
app.get('/reset/validate', (req, res) => {
  const token = String(req.query.token || '').trim();
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!token || !email) return res.status(400).json({ ok:false, msg:'token/email fehlt' });

  const db = loadTokens();
  const now = Date.now();
  const rec = db.tokens.find(t => t.email === email && t.token === token && !t.used && t.expiresAt > now);
  if (!rec) return res.status(404).json({ ok:false, msg:'ungültig oder abgelaufen' });

  return res.json({ ok:true, msg:'valid' });
});
app.head('/reset/validate', (_req, res) => res.sendStatus(200));

// Passwort endgültig setzen
app.post('/reset/confirm', (req, res) => {
  try {
    const token     = String(req.body.token || '').trim();
    const emailRaw  = String(req.body.email || '').trim();
    const email     = emailRaw.toLowerCase();
    const password  = String(req.body.password || '');
    const firstname = String(req.body.firstname || '').trim();
    const lastname  = String(req.body.lastname || '').trim();

    if (!token || !email || !password || !firstname || !lastname) {
      return res.status(400).type('text').send('Pflichtfelder fehlen');
    }

    // Stärkeprüfung: >=10, Groß+Klein + (Zahl oder Sonderz.)
    const strong = (
      password.length >= 10 &&
      /[A-Z]/.test(password) &&
      /[a-z]/.test(password) &&
      (/\d/.test(password) || /[^A-Za-z0-9]/.test(password))
    );
    if (!strong) return res.status(422).type('text').send('Passwort zu schwach');

    const db = loadTokens();
    const now = Date.now();
    const idx = db.tokens.findIndex(t => t.email === email && t.token === token && !t.used && t.expiresAt > now);
    if (idx === -1) return res.status(403).type('text').send('Token ungültig/abgelaufen');

    // Token als benutzt markieren & Altlasten aufräumen
    db.tokens[idx].used = true;
    purgeExpiredTokens(db);
    saveTokens(db);

    // Audit-Log
    const audit = {
      ts: new Date().toISOString(),
      email,
      firstname,
      lastname,
      ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString()
    };
    fs.appendFileSync(auditLogPath, JSON.stringify(audit) + '\n');

    // User anlegen/aktualisieren
    const ud = loadUsers();
    const uIdx = ud.users.findIndex(u => (u.email || '').toLowerCase() === email);
    const { algo, salt, hash } = hashPassword(password);
    const username = emailRaw.split('@')[0];

    if (uIdx === -1) {
      ud.users.push({
        email,
        username,
        firstname,
        lastname,
        passAlgo: algo,
        passSalt: salt,
        passHash: hash,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    } else {
      ud.users[uIdx] = {
        ...ud.users[uIdx],
        firstname,
        lastname,
        passAlgo: algo,
        passSalt: salt,
        passHash: hash,
        updatedAt: new Date().toISOString()
      };
    }
    saveUsers(ud);

    return res.type('text').send('Passwort gesetzt');
  } catch (err) {
    console.error('❌ Fehler /reset/confirm:', err && (err.stack || err));
    return res.status(500).type('text').send('Fehler beim Setzen des Passworts');
  }
});

// ===== Login/Logout =====
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const name = String(username || '').trim();
  const pass = String(password || '');

  const ud = loadUsers();
  const nameLower = name.toLowerCase();
  const user = ud.users.find(u =>
    (u.email && u.email.toLowerCase() === nameLower) ||
    (u.username && u.username.toLowerCase() === nameLower)
  );
  if (user && verifyPassword(pass, user)) {
    req.session.user = name;
    req.session.lastActivity = Date.now();
    return res.redirect('/after-login');
  }

  const {
    DASH_USER = '', DASH_PASS = '',
    ADMIN_USER = '', ADMIN_PASS = '',
    IBELSA_USER = '', IBELSA_PASS = ''
  } = process.env;

  const ok =
    (name === DASH_USER   && pass === DASH_PASS)   ||
    (name === ADMIN_USER  && pass === ADMIN_PASS)  ||
    (name === IBELSA_USER && pass === IBELSA_PASS);

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

// Nach Login verteilen
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) {
    setNoStore(res);
    return res.redirect('/index');
  }
  setNoStore(res);
  return res.redirect('/dashboard');
});

// ===== Routen: geschützt =====
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    setNoStore(res);
    return next();
  }
  return res.redirect('/login');
}

app.get('/index',     requireAuth, (_req, res) => res.sendFile('index.html',     { root: publicDir }));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile('dashboard.html', { root: publicDir }));

// ===== Health =====
app.get ('/health', (_req, res) => res.type('text').send('OK'));
app.head('/health', (_req, res) => res.sendStatus(200));

// ===== 404 → Login (Assets fängt static oben ab) =====
app.use((_req, res) => res.status(404).sendFile('login.html', { root: publicDir }));

// ===== Fehlerhandler =====
app.use((err, _req, res, _next) => {
  console.error('[server] Fehler:', err && err.stack || err);
  res.status(500).type('text').send('Internal Server Error');
});

// ===== Start =====
app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  console.log('ROOT      :', ROOT);
  console.log('publicDir :', publicDir);
  console.log('users.json:', usersPath);
  console.log('tokens    :', tokensPath);
  console.log('audit log :', auditLogPath);
  console.log('session idle(ms):', IDLE_MS);
});
