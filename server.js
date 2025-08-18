// /home/steven/hotel_dashboard/server.js  (CommonJS)
const express = require('express');
const path = require('path');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3011;

app.set('trust proxy', 1);

// Body-Parser
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (MemoryStore ok für Einzelprozess/PM2)
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60 * 60 * 1000 }
}));

// Rate-Limit (nur auf /login POST)
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/login', loginLimiter);

// Statische Dateien
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

// Root immer zur Login-Seite
app.get('/', (_req, res) => res.redirect('/login'));

// Lesbare Routen ohne .html
app.get('/login', (_req, res) => res.sendFile(path.join(publicDir, 'login.html')));
app.get('/status', (_req, res) => res.sendFile(path.join(publicDir, 'status.html')));
app.get('/ibelsa', (_req, res) => res.sendFile(path.join(publicDir, 'ibelsa.html')));

// Login prüfen
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const {
    DASH_USER, DASH_PASS,
    ADMIN_USER, ADMIN_PASS,
    IBELSA_USER, IBELSA_PASS
  } = process.env;

  const ok =
    (username === (DASH_USER || '')   && password === (DASH_PASS || ''))   ||
    (username === (ADMIN_USER || '')  && password === (ADMIN_PASS || ''))  ||
    (username === (IBELSA_USER || '') && password === (IBELSA_PASS || ''));

  if (!ok) return res.redirect('/login');

  req.session.user = username;
  return res.redirect('/after-login');
});

// Nach Login je nach User weiterleiten
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) {
    return res.redirect('/status');   // Admin -> Status
  }
  return res.redirect('/ibelsa');     // alle anderen -> Ibelsa
});

// Fallback 404 (optional)
app.use((_req, res) => res.status(404).sendFile(path.join(publicDir, 'login.html')));

app.listen(PORT, () => {
  console.log(`Hotel-Dashboard läuft auf Port ${PORT}`);
});
