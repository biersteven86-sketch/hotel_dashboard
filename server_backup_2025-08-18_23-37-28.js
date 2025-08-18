/* /home/steven/hotel_dashboard/server.js (CommonJS) */
const express  = require('express');
const path     = require('path');
const session  = require('express-session');
const rateLimit= require('express-rate-limit');
require('dotenv').config({ quiet: true });

const app  = express();
const PORT = process.env.PORT || 3011;

app.set('trust proxy', 1);

// Parser
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60 * 60 * 1000 }
}));

// Rate Limit nur fürs Login (POST)
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// Static
const publicDir = path.join(__dirname, 'public');
const loginFile = path.resolve(publicDir, 'login.html');   // <- absoluter Pfad
const indexFile = path.resolve(publicDir, 'index.html');
const ibelsaFile= path.resolve(publicDir, 'ibelsa.html');
const statusFile= path.resolve(publicDir, 'status.html');

app.use(express.static(publicDir, { index: false }));

// Domain-Root -> /login
app.use((req, res, next) => {
  if ((req.hostname === "hotel-dashboard.de" || req.hostname === "www.hotel-dashboard.de") &&
      (req.path === "/" || req.path === "")) {
    return res.redirect("/login");
  }
  next();
});

// Healthcheck
app.get('/health', (_req, res) => res.status(200).send('OK'));

// Root -> /login
app.get('/', (_req, res) => res.redirect('/login'));

// Saubere Routen ohne .html
app.get('/login',  (_req, res, next) => res.sendFile(loginFile,  err => err ? next(err) : undefined));
app.get('/status', (_req, res, next) => res.sendFile(statusFile, err => err ? next(err) : undefined));
app.get('/ibelsa', (_req, res, next) => res.sendFile(ibelsaFile, err => err ? next(err) : undefined));
app.get('/index',  (_req, res, next) => res.sendFile(indexFile,  err => err ? next(err) : undefined));
app.get('/index.html', (_req, res) => res.redirect('/index'));

// Login prüfen
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const { DASH_USER, DASH_PASS, ADMIN_USER, ADMIN_PASS, IBELSA_USER, IBELSA_PASS } = process.env;

  const ok =
    (username === (DASH_USER   || '') && password === (DASH_PASS   || '')) ||
    (username === (ADMIN_USER  || '') && password === (ADMIN_PASS  || '')) ||
    (username === (IBELSA_USER || '') && password === (IBELSA_PASS || ''));

  if (!ok) return res.redirect('/login');

  req.session.user = username;
  return res.redirect('/after-login');
});

// After-Login Redirect
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) return res.redirect('/index');
  return res.redirect('/ibelsa');
});

// 404 -> Login (Datei direkt)
app.use((_req, res, next) => {
  res.status(404).sendFile(loginFile, err => err ? next(err) : undefined);
});

// Fehler-Logger (hilft uns bei 500ern statt Express-Defaultseite)
app.use((err, _req, res, _next) => {
  console.error('[server] Fehler:', err && (err.stack || err));
  res.status(err.status || 500).type('text').send('Serverfehler');
});

app.listen(PORT, () => {
  console.log(`Hotel-Dashboard läuft auf Port ${PORT}`);
  console.log(`  • publicDir: ${publicDir}`);
  console.log(`  • loginFile: ${loginFile}`);
  console.log(`  • LAN:   http://${process.env.LAN_IP || ''}:${PORT}/`);
  console.log(`  • Local: http://127.0.0.1:${PORT}/`);
});
