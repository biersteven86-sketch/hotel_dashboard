// /home/steven/hotel_dashboard/server.js  (CommonJS)
const express   = require('express');
const path      = require('path');
const session   = require('express-session');
const rateLimit = require('express-rate-limit');
const os        = require('os');
require('dotenv').config({ quiet: true });   // weniger Dotenv-Noise

const app  = express();
const PORT = process.env.PORT || 3011;
const publicDir = path.join(__dirname, 'public');

app.set('trust proxy', 1);

// Parser
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (MemoryStore ok unter PM2, Einzelprozess)
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60 * 60 * 1000 }
}));

// Rate Limit nur fürs Login-POST
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// Statische Dateien (ohne auto-Index)
app.use(express.static(publicDir, { index: false }));

// www → /login
app.use((req, res, next) => {
  if ((req.hostname === 'hotel-dashboard.de' || req.hostname === 'www.hotel-dashboard.de') &&
      (req.path === '/' || req.path === '')) {
    return res.redirect('/login');
  }
  next();
});

// 1) Root immer zur Login-Seite
app.get('/', (_req, res) => res.redirect('/login'));

// 2) Lesbare Routen ohne .html
//    sendFile mit { root } verhindert Path-Probleme
app.get('/login',  (_req, res) => res.sendFile('login.html',  { root: publicDir }));
app.get('/status', (_req, res) => res.sendFile('status.html', { root: publicDir }));
app.get('/ibelsa', (_req, res) => res.sendFile('ibelsa.html', { root: publicDir }));
app.get('/index',  (_req, res) => res.sendFile('index.html',  { root: publicDir }));
app.get('/index.html', (_req, res) => res.redirect('/index'));

// 3) Login prüfen
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const {
    DASH_USER,  DASH_PASS,
    ADMIN_USER, ADMIN_PASS,
    IBELSA_USER,IBELSA_PASS
  } = process.env;

  const ok =
    (username === (DASH_USER   || '') && password === (DASH_PASS   || '')) ||
    (username === (ADMIN_USER  || '') && password === (ADMIN_PASS  || '')) ||
    (username === (IBELSA_USER || '') && password === (IBELSA_PASS || ''));

  if (!ok) return res.redirect('/login');

  req.session.user = username;
  return res.redirect('/after-login');
});

// 4) Nach Login je nach User weiterleiten
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) return res.redirect('/index');
  return res.redirect('/ibelsa');
});

// kleine Health-Route für Tests
app.get('/health', (_req, res) => res.type('text').send('OK'));

// 404 → zurück zur Login-Seite
app.use((_req, res) => res.status(404).sendFile('login.html', { root: publicDir }));

// Start + freundliche URLs ausgeben
function getLanIPv4() {
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const info of ifs[name] || []) {
      if (info && info.family === 'IPv4' && !info.internal) return info.address;
    }
  }
  return '127.0.0.1';
}

app.listen(PORT, () => {
  const ip = getLanIPv4();
  console.log('Hotel-Dashboard läuft:');
  console.log(`  • LAN:   http://${ip}:${PORT}/`);
  console.log(`  • Local: http://127.0.0.1:${PORT}/`);
});
