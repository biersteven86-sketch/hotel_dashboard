// /home/steven/hotel_dashboard/server.js  (CommonJS)
const express   = require('express');
const path      = require('path');
const session   = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ quiet: true });

const app  = express();
const PORT = process.env.PORT || 3011;

app.set('trust proxy', 1);

// Parser
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60 * 60 * 1000 }
}));

// Rate Limit NUR für POST /login
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// Static
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir, { index: false }));

// Domain-Root → /login
app.use((req, res, next) => {
  if (
    (req.hostname === 'hotel-dashboard.de' || req.hostname === 'www.hotel-dashboard.de') &&
    (req.path === '/' || req.path === '')
  ) return res.redirect('/login');
  next();
});

// Health
app.get('/health', (_req, res) => res.type('text').send('OK'));

// Root → /login
app.get('/', (_req, res) => res.redirect('/login'));

// /login robust bedienen (explicit GET) + HEAD sauber beantworten
const loginFile = path.join(publicDir, 'login.html');
app.get('/login', (_req, res, next) => {
  res.sendFile(loginFile, (err) => {
    if (err) {
      console.error('[sendFile:/login] Fehler:', err.code, err.message, '— file:', loginFile);
      next(err);
    }
  });
});
// Einige Umgebungen mappen HEAD nicht automatisch → explizit:
app.head('/login', (_req, res) => res.status(200).end());

app.get('/status', (_req, res, next) => res.sendFile(path.join(publicDir, 'status.html'), next));
app.get('/ibelsa',  (_req, res, next) => res.sendFile(path.join(publicDir, 'ibelsa.html'),  next));
app.get('/index',   (_req, res, next) => res.sendFile(path.join(publicDir, 'index.html'),   next));
// /index.html → /index
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

// 404 → login
app.use((_req, res) => res.status(404).sendFile(loginFile));

// Error-Handler (zeigt 500 im Log)
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.stack || err);
  res.status(500).type('text').send('Serverfehler');
});

app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  console.log('  • publicDir:', publicDir);
  console.log('  • loginFile:', loginFile);
});
