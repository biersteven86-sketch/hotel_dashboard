const express  = require('express');
const path     = require('path');
const session  = require('express-session');
const rateLimit= require('express-rate-limit');
require('dotenv').config({ quiet:true });

const app  = express();
const PORT = process.env.PORT || 3011;

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly:true, sameSite:'lax', secure:false, maxAge: 60*60*1000 }
}));

// Nur POST /login limitieren
const loginLimiter = rateLimit({ windowMs: 5*60*1000, max: 50, standardHeaders:true, legacyHeaders:false });

const publicDir = path.join(__dirname, 'public');

/* ---------- Auth-Guard ---------- */
function requireAuth(req, res, next){
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

/* Blocke direkte HTML-Zugriffe ohne Login (z. B. /index.html) */
app.all(/^\/(?!login(?:\/|$)|health(?:\/|$)).*\.html$/i, (req,res,next)=>{
  if (req.session && req.session.user) return next(); // eingeloggte dürfen weiter
  return res.redirect('/login');
});

/* Statische Assets (Bilder/CSS/JS) – öffentlich.
   Liegt NACH dem HTML-Blocker, damit .html ohne Login nicht ausgeliefert wird. */
app.use(express.static(publicDir, { index:false }));

// Root → /login (GET & HEAD)
app.get ('/', (_req,res)=>res.redirect('/login'));
app.head('/', (_req,res)=>res.set('Location','/login').sendStatus(302));

// Login (öffentlich)
app.get ('/login',  (_req,res)=>res.sendFile('login.html',  { root: publicDir }));
app.head('/login',  (_req,res)=>res.sendStatus(200));

// Geschützte Seiten (GET/HEAD)
app.get ('/status', requireAuth, (_req,res)=>res.sendFile('status.html', { root: publicDir }));
app.head('/status', requireAuth, (_req,res)=>res.sendStatus(200));

app.get ('/ibelsa', requireAuth, (_req,res)=>res.sendFile('ibelsa.html', { root: publicDir }));
app.head('/ibelsa', requireAuth, (_req,res)=>res.sendStatus(200));

app.get ('/index',  requireAuth, (_req,res)=>res.sendFile('index.html',  { root: publicDir }));
app.head('/index',  requireAuth, (_req,res)=>res.sendStatus(200));

// Optional: /index.html -> /index (Greift nur nach Login; ohne Login fängt der HTML-Blocker oben ab)
app.get ('/index.html', requireAuth, (_req,res)=>res.redirect('/index'));
app.head('/index.html', requireAuth, (_req,res)=>res.set('Location','/index').sendStatus(302));

// Login prüfen
app.post('/login', loginLimiter, (req,res)=>{
  const { username, password } = req.body || {};
  const { DASH_USER='',DASH_PASS='', ADMIN_USER='',ADMIN_PASS='', IBELSA_USER='',IBELSA_PASS='' } = process.env;
  const ok =
    (username===DASH_USER   && password===DASH_PASS)   ||
    (username===ADMIN_USER  && password===ADMIN_PASS)  ||
    (username===IBELSA_USER && password===IBELSA_PASS);
  if (!ok) return res.redirect('/login?err=1');
  req.session.user = username;
  return res.redirect('/after-login');
});

// Nach Login: Admin → /index, andere → /ibelsa
app.get('/after-login', (req,res)=>{
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase()===adminUser) return res.redirect('/index');
  return res.redirect('/ibelsa');
});

// Health (GET/HEAD) für Tests/Monitoring (öffentlich)
app.get ('/health', (_req,res)=>res.type('text').send('OK'));
app.head('/health', (_req,res)=>res.sendStatus(200));

// 404 → Login
app.use((_req,res)=>res.status(404).sendFile('login.html', { root: publicDir }));

// Fehlerhandler
app.use((err,_req,res,_next)=>{
  console.error('[server] Fehler:', err && err.stack || err);
  res.status(500).type('text').send('Internal Server Error');
});

app.listen(PORT, ()=>{
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  const ip = (process.env.LAN_IP) || '';
  console.log('  • publicDir:', publicDir);
});
