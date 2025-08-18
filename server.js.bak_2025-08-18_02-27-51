const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3011;

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (Memory-Store reicht fürs Dev/klein)
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60*60*1000 }
}));

// Rate-Limit nur auf /login
const loginLimiter = rateLimit({ windowMs: 5*60*1000, max: 50, standardHeaders: true, legacyHeaders: false });
app.use('/login', loginLimiter);

// Statische Dateien
const publicDir = path.join(__dirname, 'public');
// Root-Domain automatisch auf Login-Seite weiterleiten
  res.redirect("/login");
});

app.get("/", (req, res) => { res.redirect("/login"); });
app.use(express.static(publicDir));
app.get("/login", (req,res)=>res.sendFile(path.join(publicDir,"login.html")));

app.get("/ibelsa", (req,res)=>res.sendFile(path.join(publicDir,"ibelsa.html")));

app.get("/status", (req,res)=>res.sendFile(path.join(publicDir,"status.html")));

// Hilfsfunktion: wohin nach Login?
function destinationFor(user) {
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (user && user.toLowerCase() === adminUser) return '/status.html';
  return '/ibelsa.html';
}

// Root: wenn eingeloggt → ziel, sonst Login
app.get('/', (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect(destinationFor(req.session.user));
  }
  return res.redirect('/login.html');
});

// GET /login zeigt Formular-Datei
app.get('/login', (req, res) => res.redirect('/login.html'));

// POST /login prüft Zugangsdaten
app.post('/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    const aUser = process.env.ADMIN_USER || 'admin';
    const aPass = process.env.ADMIN_PASS || 'admin';

    const iUser = process.env.IBELSA_USER || '';
    const iPass = process.env.IBELSA_PASS || '';

    let ok = false;
    let who = '';

    if (username === aUser && password === aPass) {
      ok = true; who = aUser;
    } else if (username === iUser && password === iPass) {
      ok = true; who = iUser;
    }

    if (!ok) return res.status(401).redirect('/login.html?ok=false');

    // Session setzen und weiterleiten
    req.session.user = who;
    return res.redirect(destinationFor(who));
  } catch (e) {
    console.error('[LOGIN]', e);
    return res.status(500).redirect('/login.html?ok=error');
  }
});

// Logout
app.post('/logout', (req, res) => {
  req.session?.destroy(() => res.redirect('/login.html?logged_out=1'));
});

// Fallback 404 (optional)
app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => {
  console.log(`Hotel-Dashboard läuft auf Port ${PORT}`);
});
