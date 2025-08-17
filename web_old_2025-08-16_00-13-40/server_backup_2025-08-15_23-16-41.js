import dotenv from 'dotenv';
import express from 'express';
import path from 'path';
import session from 'express-session';
import { fileURLToPath } from 'url';
import ibelsa from './lib/ibelsa.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3011;

// Middleware
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'hotel-dashboard-session',
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax' }
}));

// Static files (login.html, ibelsa.html, theme.css)
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Root → Login
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login handler
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.redirect('/login.html');
  }
  req.session.user = { name: username, at: Date.now() };
  return res.redirect('/ibelsa.html');
});

// API: Hotel Info
app.get('/api/hotel-info', async (req, res) => {
  if (!process.env.IBELSA_API_KEY) {
    return res.status(500).json({ error: 'IBELSA_API_KEY fehlt (.env prüfen)' });
  }
  try {
    const data = await ibelsa('/api/hotel/information');
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message || err });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Hotel-Dashboard läuft auf Port ${PORT}`);
});
