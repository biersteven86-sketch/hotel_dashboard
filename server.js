const express   = require('express');
const path      = require('path');
const session   = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ quiet:true });

/**
 * Logohaus 3000:
 * - Läuft lokal auf :3000 (STANDARD)
 * - /reset (Passwort vergessen) öffentlich (GET/POST), ohne User-Enumeration
 * - /login öffentlich
 * - /public/* öffentlich (Assets)
 * - alle anderen Routen nur mit Session
 */

const app  = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly:true, sameSite:'lax', secure:false, maxAge: 60*60*1000 }
}));

// Rate Limit nur für Login & Reset-POST
const loginLimiter = rateLimit({ windowMs: 5*60*1000, max: 50, standardHeaders:true, legacyHeaders:false });
const resetLimiter = rateLimit({ windowMs: 5*60*1000, max: 20, standardHeaders:true, legacyHeaders:false });

const publicDir = path.join(__dirname, 'public');

// ---------- Guards ----------
const OPEN_PATHS = new Set(['/', '/login', '/health', '/reset']); // /reset GET/POST ist öffentlich

// Blocke direkte .html-Aufrufe (außer login.html & reset.html), damit URLs „sauber“ bleiben
app.use((req,res,next)=>{
  if (req.path.endsWith('.html') && req.path !== '/login.html' && req.path !== '/reset.html') {
    return res.redirect('/login');
  }
  next();
});

// Statische Assets (öffentlich)
app.use(express.static(publicDir, { index:false }));

// Globaler Auth-Guard
app.use((req, res, next) => {
  const isOpen = OPEN_PATHS.has(req.path) || req.path.startsWith('/public/') || req.path === '/login.html' || req.path === '/reset.html';
  const hasUser = !!(req.session && req.session.user);
  if (isOpen || hasUser) return next();
  return res.redirect('/login');
});

// ---------- Routen ----------

// Root -> /login
app.get ('/', (_req,res)=>res.redirect('/login'));
app.head('/', (_req,res)=>res.set('Location','/login').sendStatus(302));

// Login (GET/POST)
app.get ('/login',  (_req,res)=>res.sendFile('login.html',  { root: publicDir }));
app.head('/login',  (_req,res)=>res.sendStatus(200));

app.post('/login', loginLimiter, (req,res)=>{
  const { username, password } = req.body || {};
  const {
    DASH_USER='',DASH_PASS='',
    ADMIN_USER='',ADMIN_PASS='',
    IBELSA_USER='',IBELSA_PASS=''
  } = process.env;

  const ok =
    (username===DASH_USER   && password===DASH_PASS)   ||
    (username===ADMIN_USER  && password===ADMIN_PASS)  ||
    (username===IBELSA_USER && password===IBELSA_PASS);

  if (!ok) return res.redirect('/login?err=1');

  req.session.user = username;
  return res.redirect('/after-login');
});

// After-Login Router: Admin → /index, sonst → /ibelsa
app.get('/after-login', (req,res)=>{
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase()===adminUser) return res.redirect('/index');
  return res.redirect('/ibelsa');
});

// Geschützte Seiten (saubere URLs)
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

app.get ('/index',  requireAuth, (_req,res)=>res.sendFile('index.html',  { root: publicDir }));
app.get ('/ibelsa', requireAuth, (_req,res)=>res.sendFile('ibelsa.html', { root: publicDir }));
app.get ('/status', requireAuth, (_req,res)=>res.sendFile('status.html', { root: publicDir }));

// ---------- Passwort vergessen (/reset) ----------
// GET: Formular anzeigen
app.get('/reset', (_req,res)=>res.sendFile('reset.html', { root: publicDir }));
app.head('/reset', (_req,res)=>res.sendStatus(200));

// POST: Token/Email entgegennehmen. IMMER Erfolg melden (kein Leak ob User existiert)
app.post('/reset', resetLimiter, (req,res)=>{
  // Optional: const { emailOrUser } = req.body || {};
  // Hier würdest du einen Mail-Job/Token-Erzeugung einhängen.
  return res.redirect('/reset?sent=1');
});

// Health (öffentlich)
app.get ('/health', (_req,res)=>res.type('text').send('OK'));
app.head('/health', (_req,res)=>res.sendStatus(200));

// 404 → Login
app.use((_req,res)=>res.status(404).sendFile('login.html', { root: publicDir }));

// Fehlerhandler
app.use((err,_req,res,_next)=>{
  console.error('[server] Fehler:', err && err.stack || err);
  res.status(500).type('text').send('Internal Server Error');
});

// Start
app.listen(PORT, ()=>{
  console.log('Hotel-Dashboard (Logohaus 3000) läuft auf Port', PORT);
  console.log('  • publicDir:', publicDir);
});
