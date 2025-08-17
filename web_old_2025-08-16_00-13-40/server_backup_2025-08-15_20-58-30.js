import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import { ibelsa } from './lib/ibelsa.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const app  = express();
app.use(require(./routes/auth));
const PORT = process.env.PORT || 3011;

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true })); // für HTML-Form
app.use(express.json());

// Static Files aus /public
app.use(express.static(path.join(__dirname, 'public')));

// Root -> Login
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// ✅ FIX: POST /login -> Redirect auf /ibelsa.html
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).send('Bitte Benutzername und Passwort eingeben.');
  return res.redirect(302, '/ibelsa.html');
});

// Server-API: ibelsa Hotel-Informationen (Key bleibt serverseitig!)
app.get('/api/hotel-info', async (_req, res) => {
  try {
    const data = await ibelsa('/api/hotel/information'); // ibelsa Endpoint:contentReference[oaicite:4]{index=4}:contentReference[oaicite:5]{index=5}
    return res.json(data.data ?? data);
  } catch (e) {
    return res.status(e.status || 500).send(e.message || 'Fehler bei ibelsa');
  }
});

// 404-Fallback (freundlicher als "Cannot POST /...")
app.use((req, res) => res.status(404).send(`Pfad nicht gefunden: ${req.method} ${req.path}`));

app.listen(PORT, () => console.log(`[hotel-dashboard] Server läuft auf Port ${PORT}`));
