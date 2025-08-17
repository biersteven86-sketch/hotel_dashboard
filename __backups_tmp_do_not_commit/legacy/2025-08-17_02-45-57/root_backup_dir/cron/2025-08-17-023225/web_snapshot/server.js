// /home/steven/hotel_dashboard/web/server.js  (CommonJS-Version)
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3011;

app.set('trust proxy', 1); // hinter Apache/Proxy sinnvoll:contentReference[oaicite:6]{index=6}

// Parser für Form-POST & JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (einfacher Memory-Store)
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 60 * 60 * 1000 }
}));

// Rate-Limit nur auf /login
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/login', loginLimiter);

// Static-Files
const publicDir = path.join(__dirname, 'public'); // enthält login.html / ibelsa.html / index.html / status.html:contentReference[oaicite:7]{index=7}
app.use(express.static(publicDir));

// Users laden (aus /web/users.json)
const usersFile = path.join(__dirname, 'users.json');
let users = [];
try {
  if (fs.existsSync(usersFile)) {
    users = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    if (!Array.isArray(users)) throw new Error('users.json muss ein Array sein');
  } else {
    console.warn('[WARN] users.json fehlt – Default-Nutzer aktiv (nur Test)');
    users = [
      { username: 'admin', password: 'test', redirect: '/index.html' },
      { username: 'max',   password: 'test', redirect: '/ibelsa.html' }
    ];
  }
} catch (e) {
  console.error('[ERROR] users.json:', e.message);
  users = []; // blockiere Logins bei Fehler
}

// Helper: Zielseite ermitteln (users.json > Sonderfall admin > Standard)
function resolveTarget(user) {
  // 1) Redirect aus users.json respektieren, falls vorhanden
  const raw = (user && user.redirect) ? String(user.redirect).trim() : '';
  if (raw) {
    // Path härten: führenden Slash erzwingen
    return raw.startsWith('/') ? raw : `/${raw}`;
  }
  // 2) Sonderfall admin (Fallback, falls kein redirect gesetzt)
  const uname = String(user.username || '').trim().toLowerCase();
  if (uname === 'admin') return '/index.html';
  // 3) Standardziel
  return '/ibelsa.html';
}

// Routes
app.get('/', (_req, res) => res.sendFile(path.join(publicDir, 'login.html')));

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find(u => String(u?.username) === String(username) && String(u?.password) === String(password));

  if (!user) {
    return res.status(401).send('Ungültige Zugangsdaten');
  }

  // Session minimal setzen (optional später erweitern)
  req.session.user = { username: String(user.username) };

  const target = resolveTarget(user);

  console.log(`[LOGIN] user=${user.username} -> ${target}`);
  return res.redirect(303, target); // PRG (POST → Redirect → GET)
});

// optionaler Logout
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// Fehler-Handler
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err);
  res.status(500).send('Interner Serverfehler');
});

// Start
app.listen(PORT, () => {
  console.log(`Hotel-Dashboard läuft auf Port ${PORT}`);
});
