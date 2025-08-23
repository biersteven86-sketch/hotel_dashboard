// server.js – Hotel-Dashboard (Logohaus 3000 ready)
// Läuft lokal standardmäßig auf :3000, in Prod via $PORT

const express   = require('express');
const path      = require('path');
const session   = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ quiet: true });

const app   = express();
const isProd= process.env.NODE_ENV === 'production';
const PORT  = process.env.PORT || 3000; // lokal 3000; Hosting (Render/Proxy) setzt $PORT

// Proxy (für X-Forwarded-* & HTTPS cookies hinter Proxy)
app.set('trust proxy', 1);

// Parser
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,            // hinter HTTPS true, lokal false
    maxAge: 60 * 60 * 1000     // 1h
  }
}));

// Rate-Limit nur für POST /login
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// Pfade
const publicDir = path.join(__dirname, 'public');

// ---- Global-Guard -----------------------------------------------------------
// Offen: Root, Login/Reset, Health, /public/*
const OPEN_PATHS = new Set(['/', '/login', '/reset', '/health']);
app.use((req, res, next) => {
  const isOpen = OPEN_PATHS.has(req.path) || req.path.startsWith('/public/');
  const hasUser = !!(req.session && req.session.user);
  if (isOpen || hasUser) return next();
  return res.redirect('/login');
});

// Direkte .html-Requests blocken (Ausnahmen: login.html, reset.html)
app.use((req, res, next) => {
  if (req.path.endsWith('.html') && !['/login.html','/reset.html'].includes(req.path)) {
    return res.redirect('/login');
  }
  next();
});

// Statische Assets (ohne Auto-Index)
app.use(express.static(publicDir, { index: false }));

// ---- Helper ----------------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

// ---- Open Routes ------------------------------------------------------------
// Root leitet auf /login
app.get ('/',          (_req, res) => res.redirect('/login'));
app.head('/',          (_req, res) => res.set('Location','/login').sendStatus(302));

// Login-Seite
app.get ('/login',     (_req, res) => res.sendFile('login.html',  { root: publicDir }));
app.head('/login',     (_req, res) => res.sendStatus(200));

// Passwort-vergessen-Seite (du legst public/reset.html ab)
app.get ('/reset',     (_req, res) => res.sendFile('reset.html',  { root: publicDir }));
app.head('/reset',     (_req, res) => res.sendStatus(200));

// Health
app.get ('/health',    (_req, res) => res.type('text').send('OK'));
app.head('/health',    (_req, res) => res.sendStatus(200));

// ---- Auth-geschützte Seiten -------------------------------------------------
app.get ('/index',     requireAuth, (_req, res) => res.sendFile('index.html',  { root: publicDir }));
app.get ('/ibelsa',    requireAuth, (_req, res) => res.sendFile('ibelsa.html', { root: publicDir }));
app.get ('/status',    requireAuth, (_req, res) => res.sendFile('status.html', { root: publicDir }));

// Saubere URLs (optional: hier nur Beispiel für /index.html)
app.get('/index.html', (_req, res) => res.redirect('/index'));

// ---- Auth -------------------------------------------------------------------
// Login prüfen
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const {
    DASH_USER = '', DASH_PASS = '',
    ADMIN_USER = '', ADMIN_PASS = '',
    IBELSA_USER = '', IBELSA_PASS = ''
  } = process.env;

  const ok =
    (username === DASH_USER   && password === DASH_PASS)   ||
    (username === ADMIN_USER  && password === ADMIN_PASS)  ||
    (username === IBELSA_USER && password === IBELSA_PASS);

  if (!ok) return res.redirect('/login?err=1');

  req.session.user = username;
  return res.redirect('/after-login');
});

// Post-Login Routing
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) return res.redirect('/index');
  return res.redirect('/ibelsa');
});

// Logout
app.post('/logout', (req, res) => {
  req.session?.destroy(() => res.redirect('/login'));
});

// ---- Fallbacks & Fehler -----------------------------------------------------
// 404 → Login-Seite
app.use((_req, res) => res.status(404).sendFile('login.html', { root: publicDir }));

// Fehlerhandler
app.use((err, _req, res, _next) => {
  console.error('[server] Fehler:', err && err.stack || err);
  res.status(500).type('text').send('Internal Server Error');
});

// ---- Start ------------------------------------------------------------------
app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  console.log('  • publicDir:', publicDir);
  console.log('  • NODE_ENV :', process.env.NODE_ENV || 'development');
});
