/**
 * Hotel Dashboard server – vollständige Drop-in-Version
 * Stellt sicher: POST /login -> Redirect auf /ibelsa.html
 * Dient /public als Static, stellt /api/hotel-info bereit (ibelsa-Proxy)
 */
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT || 3011;

// Middlewares
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true })); // für HTML-Form POST (username/password)
app.use(express.json());                         // falls wir mal JSON empfangen

// Static /public
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

// Optional: / auf Login (falls index.html leer ist)
app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'login.html')));

// LOGIN: nimmt Formfelder an und leitet um
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  // Minimalprüfung – hier kannst du echte Prüfung einbauen
  if (!username || !password) {
    return res.status(400).send('Benutzername/Passwort fehlen.');
  }
  // ✅ Nach erfolgreicher "Prüfung": weiter zur App
  return res.redirect(302, '/ibelsa.html');
});

// LOGOUT: zurück zum Login
app.get('/logout', (_req, res) => res.redirect(302, '/login.html'));

// ---------- API: ibelsa Hotel-Informationen ----------
const IBELSA_API_BASE = process.env.IBELSA_API_BASE || 'https://rooms.ibelsa.com';
const IBELSA_API_KEY  = process.env.IBELSA_API_KEY || '';

app.get('/api/hotel-info', async (_req, res) => {
  if (!IBELSA_API_KEY) {
    return res.status(500).json({ success:false, message:'IBELSA_API_KEY fehlt (siehe .env)' });
  }
  try {
    const url = `${IBELSA_API_BASE}/api/hotel/information`;
    const r = await fetch(url, {
      method: 'GET',
      headers: { 'x-ibelsa-key': IBELSA_API_KEY },
      redirect: 'follow'
    });
    const json = await r.json();
    if (!r.ok || json?.success === false) {
      return res.status(r.status).json({ success:false, message:'ibelsa Fehler', data: json });
    }
    // Frontend erwartet nur die Daten
    return res.json(json.data ?? json);
  } catch (e) {
    return res.status(500).json({ success:false, message: String(e) });
  }
});

// Fallback 404 (schöne Meldung statt "Cannot POST /...")
app.use((req, res) => {
  res.status(404).send(`Pfad nicht gefunden: ${req.method} ${req.path}`);
});

app.listen(PORT, () => {
  console.log(`[hotel-dashboard] Server läuft auf Port ${PORT}`);
});
