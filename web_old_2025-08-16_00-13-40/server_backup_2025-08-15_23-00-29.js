const path = require('path');
const express = require('express');
const session = require('express-session');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 3011;

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'hotel-dashboard-session',
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax' }
}));

// Statische Dateien (ohne auto-Index)
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Root -> Login
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login: nach erfolgreichem POST auf ibelsa.html umleiten
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.redirect('/login.html');
  req.session.user = { name: username, at: Date.now() };
  return res.redirect('/ibelsa.html');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// API: Hotel-Informationen via ibelsa
app.get('/api/hotel-info', async (_req, res) => {
  try {
    const base = process.env.IBELSA_API_BASE || 'https://rooms.ibelsa.com';
    const key  = process.env.IBELSA_API_KEY;
    if (!key) return res.status(500).json({ success:false, message:'IBELSA_API_KEY fehlt' });

    const r = await fetch(`${base}/api/hotel/information`, {
      headers: { 'x-ibelsa-key': key }
    });

    const txt = await r.text();
    let json; try { json = JSON.parse(txt); } catch {
      return res.status(502).type('text').send(txt.slice(0,500));
    }
    if (!r.ok || json.success === false) {
      return res.status(r.status).json(json);
    }
    return res.json(json.data || json);
  } catch (err) {
    return res.status(500).json({ success:false, message:String(err) });
  }
});

// Healthcheck & 404
app.get('/healthz', (_req, res) => res.type('text').send('ok'));
app.use((_req, res) => res.status(404).type('text').send('Not Found'));

app.listen(PORT, () => {
  console.log(`[hotel-dashboard] Server läuft auf Port ${PORT}`);
});
