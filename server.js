/**
 * /home/steven/hotel_dashboard/server.js
 * Express-App mit robusten Routen für GET/HEAD + Healthcheck.
 * (CommonJS)
 */
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

// Sessions
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60 * 60 * 1000 }
}));

// Rate-Limit NUR für POST /login
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

// Statisch
const publicDir = path.join(__dirname, 'public');
const loginFile = path.join(publicDir, 'login.html');
const indexFile = path.join(publicDir, 'index.html');
const statusFile= path.join(publicDir, 'status.html');
const ibelsaFile= path.join(publicDir, 'ibelsa.html');

app.use(express.static(publicDir, { index: false }));

// Debug-Log (sehr knapp)
app.use((req, _res, next) => { 
  if (req.path === '/' || req.path === '/login' || req.path === '/health') {
    console.log(`[req] ${req.method} ${req.path}`);
  }
  next();
});

// Health
app.get('/health', (_req, res) => res.status(200).type('text/plain').send('OK'));
app.head('/health', (_req, res) => res.status(200).end());

// Root → /login (GET & HEAD)
function redirectToLogin(_req, res) { return res.redirect('/login'); }
app.get('/', redirectToLogin);
app.head('/', (_req, res) => res.set('Location', '/login').status(302).end());

// Saubere Routen (GET & HEAD)
app.get('/login',  (_req, res) => res.sendFile(loginFile));
app.head('/login', (_req, res) => res.status(200).end());

app.get('/status', (_req, res) => res.sendFile(statusFile));
app.head('/status', (_req, res) => res.status(200).end());

app.get('/ibelsa', (_req, res) => res.sendFile(ibelsaFile));
app.head('/ibelsa', (_req, res) => res.status(200).end());

app.get('/index',  (_req, res) => res.sendFile(indexFile));
app.head('/index', (_req, res) => res.status(200).end());

// Optional: /index.html → /index
app.get('/index.html', (_req, res) => res.redirect('/index'));
app.head('/index.html', (_req, res) => res.set('Location','/index').status(302).end());

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

// Nach Login: Admin → /index, andere → /ibelsa
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) return res.redirect('/index');
  return res.redirect('/ibelsa');
});

// 404 → Login (GET & HEAD)
app.use((req, res) => {
  if (req.method === 'HEAD') return res.status(200).end();
  return res.status(404).sendFile(loginFile);
});

// Start
app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  console.log('  • publicDir :', publicDir);
  console.log('  • loginFile :', loginFile);
  console.log('  • LAN      : http://' + (process.env.LAN_IP || '172.15.0.73') + ':' + PORT + '/');
  console.log('  • Local    : http://127.0.0.1:' + PORT + '/');
});
