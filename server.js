cat > /home/steven/hotel_dashboard/server.js <<'EOF'
const express   = require('express');
const path      = require('path');
const session   = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ quiet: true });

const app  = express();
// Lokal 3000, sonst $PORT (z.B. Render). Siehe Projekt-Referenz.
const PORT = process.env.PORT || 3000; // :contentReference[oaicite:2]{index=2}

// --- Basics ---
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Session ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, sameSite: 'lax', secure: false,
    maxAge: 60 * 60 * 1000
  }
}));

// --- Rate Limit nur für Login ---
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});

const BASE      = '/home/steven/hotel_dashboard';
const publicDir = path.join(BASE, 'public');

// --- Global Guard: nur /login, /reset, /health und /public/* sind offen ---
const OPEN_PATHS = new Set(['/', '/login', '/reset', '/health']);
app.use((req, res, next) => {
  const isOpen  = OPEN_PATHS.has(req.path) || req.path.startsWith('/public/');
  const hasUser = !!(req.session && req.session.user);
  if (isOpen || hasUser) return next();
  return res.redirect('/login');
});

// --- NIE direkt .html ausliefern (außer login.html via dedizierter Route) ---
app.use((req, res, next) => {
  if (req.path.endsWith('.html') && req.path !== '/login.html') {
    return res.redirect('/login');
  }
  next();
});

// --- BACKUP/TEMP-Dateien strikt blocken (auch unter /public) ---
const BACKUP_BLOCK_RE = /(^|(?:\/))(
    .*_backup_.*|
    .*\.bak(?:[._].*|$)|
    .*~$|
    .*\.old(?:[._].*|$)|
    .*\.save(?:[._].*|$)
  )/ix;

app.use((req, res, next) => {
  if (req.path.startsWith('/public/') && BACKUP_BLOCK_RE.test(req.path)) {
    return res.status(404).type('text').send('Not Found');
  }
  next();
});

// --- Statische Dateien (ohne Directory Index, keine Dotfiles) ---
app.use(express.static(publicDir, {
  index: false,
  dotfiles: 'ignore',
  fallthrough: true,
  etag: true,
  maxAge: '1h',
}));

// --- Auth-Guard Helfer für /index, /ibelsa, /status ---
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

// --- Root → /login (bestätigt im Projekt-Referenz-Dokument) ---
app.get('/', (_req, res) => res.redirect('/login'));
app.head('/', (_req, res) => res.set('Location', '/login').sendStatus(302));

// --- Login (öffentlich) ---
app.get('/login',  (_req, res) => res.sendFile('login.html',  { root: publicDir }));
app.head('/login', (_req, res) => res.sendStatus(200));

// --- Reset (öffentlich, weil Link von Login-Seite) ---
app.get('/reset',  (_req, res) => res.sendFile('reset.html',  { root: publicDir }));
app.head('/reset', (_req, res) => res.sendStatus(200));

// --- Geschützte Seiten ---
app.get('/index',  requireAuth, (_req, res) => res.sendFile('index.html',  { root: publicDir }));
app.get('/ibelsa', requireAuth, (_req, res) => res.sendFile('ibelsa.html', { root: publicDir }));
app.get('/status', requireAuth, (_req, res) => res.sendFile('status.html', { root: publicDir }));

// --- Login prüfen ---
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const {
    DASH_USER = '', DASH_PASS = '',
    ADMIN_USER = '', ADMIN_PASS = '',
    IBELSA_USER = '', IBELSA_PASS = '',
  } = process.env;

  const ok =
    (username === DASH_USER   && password === DASH_PASS)   ||
    (username === ADMIN_USER  && password === ADMIN_PASS)  ||
    (username === IBELSA_USER && password === IBELSA_PASS);

  if (!ok) return res.redirect('/login?err=1');

  req.session.user = username;
  return res.redirect('/after-login');
});

// --- Nach Login: Admin → /index, alle anderen → /ibelsa ---
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) return res.redirect('/index');
  return res.redirect('/ibelsa');
});

// --- Health (öffentlich) ---
app.get('/health', (_req, res) => res.type('text').send('OK'));
app.head('/health', (_req, res) => res.sendStatus(200));

// --- 404 → Login ---
app.use((_req, res) => res.status(404).sendFile('login.html', { root: publicDir }));

// --- Fehlerhandler ---
app.use((err, _req, res, _next) => {
  console.error('[server] Fehler:', err && err.stack || err);
  res.status(500).type('text').send('Internal Server Error');
});

app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  console.log('  • publicDir:', publicDir);
});
EOF
