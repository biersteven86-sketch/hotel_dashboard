import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import { ibelsa } from './lib/ibelsa.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3011;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Default route → login
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// LOGIN handler
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).send('Bitte Benutzername und Passwort eingeben.');
  }
  // Erfolgreich → weiter zu ibelsa.html
  return res.redirect('/ibelsa.html');
});

// API proxy for hotel info
app.get('/api/hotel-info', async (_req, res) => {
  try {
    const data = await ibelsa('/api/hotel/information');
    return res.json(data.data);
  } catch (err) {
    return res.status(err.status || 500).send(err.message || 'Fehler bei ibelsa');
  }
});

// 404 fallback
app.use((req, res) => res.status(404).send(`Pfad nicht gefunden: ${req.method} ${req.path}`));

app.listen(PORT, () => console.log(`[hotel-dashboard] Läuft auf Port ${PORT}`));
