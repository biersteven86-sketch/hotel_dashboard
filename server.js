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
const ROOT = process.env.HD_ROOT ? path.resolve(process.env.HD_ROOT) : path.resolve(__dirname);
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
    return { tokens: Array.isArray(parsed?.tokens) ? parsed.tokens : [] };
  } catch { return { tokens: [] }; }
}
function saveTokens(obj) {
  fs.writeFileSync(tokensPath, JSON.stringify({ tokens: obj.tokens || [] }, null, 2), 'utf8');
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
    return { users: Array.isArray(parsed?.users) ? parsed.users : [] };
  } catch { return { users: [] }; }
}
function saveUsers(obj) {
  fs.writeFileSync(usersPath, JSON.stringify({ users: obj.users || [] }, null, 2), 'utf8');
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
  const parts = String(user.passAlgo || '').split(':');
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

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60 * 60 * 1000 }
}));

// RateLimit nur auf POST /login
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// Statische Assets zuerst
app.use(express.static(publicDir, { index: false }));

// ===== Guards =====
const OPEN_PATHS = new Set([
  '/', '/login', '/health',
  '/reset', '/reset.html',
  '/reset/validate', '/reset/confirm'
]);
const assetRE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map)$/i;

app.use((req, res, next) => {
  if (assetRE.test(req.path)) return next();
  if (OPEN_PATHS.has(req.path)) return next();
  if (req.path.startsWith('/public/')) return next();
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
});

// Direkte .html Aufrufe blocken (außer login/reset)
app.use((req, res, next) => {
  if (req.path.endsWith('.html') && req.path !== '/login.html' && req.path !== '/reset.html') {
    return res.redirect('/login');
  }
  next();
});

// ===== Routen: öffentlich =====
app.get('/', (_req, res) => res.redirect('/login'));
app.get('/login', (_req, res) => res.sendFile('login.html', { root: publicDir }));
app.get('/reset', (_req, res) => res.sendFile('reset.html', { root: publicDir }));

// POST /reset → JSON-Antwort
app.post('/reset', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ ok:false, message:'E-Mail fehlt' });

    const token = Math.random().toString(36).slice(2, 10);
    const now   = Date.now();
    const exp   = now + 30 * 60 * 1000;

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
      text: `Dein Code lautet: ${token}\n\nOder klicke: ${verifyUrl}`,
      html: `<p>Dein Code lautet: <b>${token}</b></p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
    });

    console.log('✅ Reset-Mail verschickt:', info.messageId, '→', email);
    return res.status(200).json({ ok:true, message:'Mail sent', redirect:'/reset?sent=1' });
  } catch (err) {
    console.error('❌ Fehler /reset:', err && (err.stack || err));
    return res.status(500).json({ ok:false, message:'Mailversand fehlgeschlagen' });
  }
});

// ===== Beispiel: weitere Routen (Login, confirm usw. bleiben wie gehabt) =====
// ... deine bisherigen /reset/validate, /reset/confirm, /login, /after-login, /index, /admin etc. hier unverändert ...

// Start
app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
});
