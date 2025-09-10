// server.js — Hotel-Dashboard (Reset-Flow erweitert)
// Läuft hinter NGINX (80/443) → Node/Express auf PORT (Default 3000)

require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');

const app = express();

// --- Konfiguration / Umgebungsvariablen ---
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const APP_BASE_URL = process.env.APP_BASE_URL || `http://127.0.0.1:${PORT}`;

// Optional: SMTP für E-Mail-Versand (falls vorhanden)
// Falls bei dir bereits ein Mailer im Einsatz ist, bleibt das hier ungenutzt.
// Diese Datei bricht NICHT, wenn SMTP nicht gesetzt ist.
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const MAIL_FROM  = process.env.MAIL_FROM  || 'no-reply@hotel-dashboard.de';

// --- Dateien / Speicher ---
const DATA_DIR = path.resolve(__dirname);
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TOKENS_FILE = path.join(DATA_DIR, 'reset_tokens.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.log');

// Hilfsfunktion: sichere Datei-Initialisierung
async function ensureFileJSON(filePath, initialValue) {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
  } catch {
    await fsp.writeFile(filePath, JSON.stringify(initialValue, null, 2));
  }
}

// Hilfsfunktion: JSON laden/speichern
async function readJSON(filePath, fallback) {
  try {
    const raw = await fsp.readFile(filePath, 'utf8');
    return JSON.parse(raw || 'null') ?? fallback;
  } catch {
    return fallback;
  }
}
async function writeJSON(filePath, obj) {
  await fsp.writeFile(filePath, JSON.stringify(obj, null, 2));
}

// IP-Ermittlung (für Audit)
function getClientIP(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length > 0) {
    return xf.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '';
}

// Audit-Log
async function auditLog(event, details) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    event,
    ...details
  }) + '\n';
  await fsp.appendFile(AUDIT_FILE, line);
}

// Primitive E-Mail-Versand (nur wenn SMTP gesetzt, sonst noop)
async function sendMail(to, subject, text) {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    // Kein SMTP konfiguriert → nur loggen
    await auditLog('mail.noop', { to, subject });
    return;
  }
  // Lazy import, um Abhängigkeit zu vermeiden, wenn ungenutzt
  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  await transporter.sendMail({ from: MAIL_FROM, to, subject, text });
}

// Passwort-Policy: ≥10 Zeichen, Groß- & Kleinbuchstabe, Ziffer ODER Sonderzeichen
function validatePasswordPolicy(pw) {
  if (typeof pw !== 'string' || pw.length < 10) return false;
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSpecial = /[^A-Za-z0-9]/.test(pw);
  if (!hasLower || !hasUpper) return false;
  if (!(hasDigit || hasSpecial)) return false;
  return true;
}

// Rate Limits für Reset-Endpoints
const resetLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Static (public)
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html']
}));

// Init Dateien
(async () => {
  await ensureFileJSON(USERS_FILE, []);
  await ensureFileJSON(TOKENS_FILE, []);
  try {
    await fsp.access(AUDIT_FILE, fs.constants.F_OK);
  } catch {
    await fsp.writeFile(AUDIT_FILE, '');
  }
})().catch(err => {
  console.error('Init error:', err);
});

// ---------- LOGIN-FLOW (Beispiel) ----------
app.post('/login', async (req, res) => {
  // Placeholder – dein bestehender Login bleibt unberührt.
  res.redirect('/ibelsa.html');
});

// ---------- PASSWORT-RESET: Token anfordern (bestehend) ----------
app.post('/reset', resetLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const ip = getClientIP(req);

    if (!email) {
      return res.status(400).send('Email required');
    }

    const tokens = await readJSON(TOKENS_FILE, []);
    // Token erzeugen
    const token = crypto.randomBytes(24).toString('base64url'); // URL-sicher
    const expiresAt = Date.now() + (1000 * 60 * 30); // 30 Minuten

    // vorhandene Tokens der Mail invalidieren (optional, um nur 1 aktiv zu lassen)
    for (const t of tokens) {
      if (t.email === email && !t.used) t.used = true;
    }

    tokens.push({
      email,
      token,
      createdAt: Date.now(),
      expiresAt,
      used: false
    });
    await writeJSON(TOKENS_FILE, tokens);

    const resetLink = `${APP_BASE_URL}/reset.html?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
    // Mail senden (oder noop)
    await sendMail(email, 'Hotel-Dashboard: Passwort zurücksetzen', 
      `Hallo,\n\nbitte klicke auf folgenden Link, um dein Passwort zurückzusetzen:\n\n${resetLink}\n\nDer Link ist 30 Minuten gültig.\n\nViele Grüße\nHotel-Dashboard`
    );

    await auditLog('reset.mail.sent', { email, ip });

    // Nach Versand zurück auf reset.html mit Hinweis (Frontend macht aktuell 5s Redirect)
    res.status(200).json({ ok: true, message: 'Mail sent', redirect: '/reset.html?sent=1' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal error');
  }
});

// ---------- NEU: Token validieren ----------
app.get('/reset/validate', resetLimiter, async (req, res) => {
  try {
    const email = String(req.query.email || '').trim().toLowerCase();
    const token = String(req.query.token || '').trim();

    if (!email || !token) {
      return res.status(400).json({ ok: false, error: 'missing_parameters' });
    }

    const tokens = await readJSON(TOKENS_FILE, []);
    const hit = tokens.find(t => t.email === email && t.token === token);

    if (!hit) {
      return res.status(400).json({ ok: false, error: 'invalid_token' });
    }
    if (hit.used) {
      return res.status(400).json({ ok: false, error: 'token_used' });
    }
    if (Date.now() > hit.expiresAt) {
      return res.status(400).json({ ok: false, error: 'token_expired' });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ---------- NEU: Passwort setzen & Audit ----------
app.post('/reset/confirm', resetLimiter, async (req, res) => {
  try {
    const ip = getClientIP(req);
    const email = String(req.body.email || '').trim().toLowerCase();
    const token = String(req.body.token || '').trim();
    const firstname = String(req.body.firstname || '').trim();
    const lastname = String(req.body.lastname || '').trim();
    const password = String(req.body.password || '');

    // Pflichtfelder prüfen
    if (!email || !token || !firstname || !lastname || !password) {
      return res.status(400).json({ ok: false, error: 'missing_parameters' });
    }

    // Token prüfen
    const tokens = await readJSON(TOKENS_FILE, []);
    const idx = tokens.findIndex(t => t.email === email && t.token === token);
    if (idx === -1) {
      return res.status(400).json({ ok: false, error: 'invalid_token' });
    }
    const t = tokens[idx];
    if (t.used) {
      return res.status(400).json({ ok: false, error: 'token_used' });
    }
    if (Date.now() > t.expiresAt) {
      return res.status(400).json({ ok: false, error: 'token_expired' });
    }

    // Passwort-Policy
    if (!validatePasswordPolicy(password)) {
      return res.status(422).json({ 
        ok: false, 
        error: 'weak_password',
        policy: 'min 10 chars, upper+lower, and digit or special'
      });
    }

    // Hash erzeugen
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);

    // users.json aktualisieren (create or update)
    const users = await readJSON(USERS_FILE, []);
    const uIdx = users.findIndex(u => (u.email || '').toLowerCase() === email);
    const userRecord = {
      email,
      // Hinweis: Keine personenbezogenen Daten dauerhaft speichern (Vor-/Nachname nur im Audit-Log)
      passwordHash: hash,
      passwordUpdatedAt: new Date().toISOString()
    };
    if (uIdx === -1) {
      users.push(userRecord);
    } else {
      users[uIdx] = { ...users[uIdx], ...userRecord };
    }
    await writeJSON(USERS_FILE, users);

    // Token invalidieren
    tokens[idx].used = true;
    await writeJSON(TOKENS_FILE, tokens);

    // Audit schreiben
    await auditLog('reset.confirm', { email, firstname, lastname, ip });

    // Fertig
    return res.status(200).json({ ok: true, redirect: '/login.html?reset=1' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Health / Root
app.get('/', (req, res) => {
  res.status(200).send('Hotel-Dashboard OK');
});

// Fallback 404 (für API)
app.use((req, res) => {
  res.status(404).send('Not Found');
});

app.listen(PORT, () => {
  console.log(`Hotel-Dashboard listening on ${PORT}`);
});
