// server.js — Hotel-Dashboard (Admin-Dashboard + Health + Status + Actions + PBKDF2)
// Hinweis: keine externen neuen Abhängigkeiten nötig.

require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const { execFile } = require('child_process');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');

const app = express();

// --- Konfiguration ---
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const APP_BASE_URL = process.env.APP_BASE_URL || `http://127.0.0.1:${PORT}`;
const REPO_DIR = '/home/steven/hotel_dashboard';

// SMTP optional (noop wenn nicht gesetzt)
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const MAIL_FROM  = process.env.MAIL_FROM  || 'no-reply@hotel-dashboard.de';

// Dateien
const DATA_DIR   = path.resolve(__dirname);
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TOKENS_FILE= path.join(DATA_DIR, 'reset_tokens.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.log');

// Helpers
async function ensureFileJSON(filePath, initialValue) {
  try { await fsp.access(filePath, fs.constants.F_OK); }
  catch { await fsp.writeFile(filePath, JSON.stringify(initialValue, null, 2)); }
}
async function readJSON(filePath, fallback) {
  try { const raw = await fsp.readFile(filePath, 'utf8'); return JSON.parse(raw || 'null') ?? fallback; }
  catch { return fallback; }
}
async function writeJSON(filePath, obj) {
  await fsp.writeFile(filePath, JSON.stringify(obj, null, 2));
}
function getClientIP(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length > 0) return xf.split(',')[0].trim();
  return req.socket?.remoteAddress || '';
}
async function auditLog(event, details) {
  const line = JSON.stringify({ ts: new Date().toISOString(), event, ...details }) + '\n';
  await fsp.appendFile(AUDIT_FILE, line);
}
async function sendMail(to, subject, text) {
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) { await auditLog('mail.noop', { to, subject }); return; }
  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  await transporter.sendMail({ from: MAIL_FROM, to, subject, text });
}

// ===== PBKDF2 (sha256, 310000) – kompatibel zu users.json =====
const PBKDF2_DIGEST = 'sha256';
const PBKDF2_ITERS  = 310000;
const PBKDF2_LEN    = 32;
function hashPasswordPBKDF2(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const dk = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERS, PBKDF2_LEN, PBKDF2_DIGEST);
  return dk.toString('hex');
}
function createPasswordRecord(password) {
  const saltHex = crypto.randomBytes(16).toString('hex');
  const hashHex = hashPasswordPBKDF2(password, saltHex);
  return { passAlgo: `pbkdf2:${PBKDF2_DIGEST}:${PBKDF2_ITERS}`, passSalt: saltHex, passHash: hashHex };
}

// Policy
function validatePasswordPolicy(pw) {
  if (typeof pw !== 'string' || pw.length < 10) return false;
  const hasLower=/[a-z]/.test(pw), hasUpper=/[A-Z]/.test(pw), hasDigit=/\d/.test(pw), hasSpecial=/[^A-Za-z0-9]/.test(pw);
  if (!hasLower || !hasUpper) return false; if (!(hasDigit || hasSpecial)) return false; return true;
}

// Rate Limit
const resetLimiter = rateLimit({ windowMs:60*1000, max:30, standardHeaders:true, legacyHeaders:false });

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// Init
(async () => {
  await ensureFileJSON(USERS_FILE, []);
  await ensureFileJSON(TOKENS_FILE, []);
  try { await fsp.access(AUDIT_FILE, fs.constants.F_OK); } catch { await fsp.writeFile(AUDIT_FILE, ''); }
})().catch(err => console.error('Init error:', err));

// ---------- HEALTH ----------
app.get('/health', (req, res) => {
  res.status(200).json({ ok:true, ts:new Date().toISOString(), port:PORT });
});

// ---------- LOGIN (Placeholder – wie gehabt) ----------
app.post('/login', async (req, res) => {
  res.redirect('/ibelsa.html');
});

// ---------- RESET: Token anfordern ----------
app.post('/reset', resetLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const ip = getClientIP(req);
    if (!email) return res.status(400).send('Email required');

    const tokens = await readJSON(TOKENS_FILE, []);
    for (const t of tokens) if (t.email===email && !t.used) t.used = true;
    const token = crypto.randomBytes(24).toString('base64url');
    const expiresAt = Date.now() + 30*60*1000;
    tokens.push({ email, token, createdAt: Date.now(), expiresAt, used:false });
    await writeJSON(TOKENS_FILE, tokens);

    const resetLink = `${APP_BASE_URL}/reset.html?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
    await sendMail(email, 'Hotel-Dashboard: Passwort zurücksetzen', `Hallo,\n\nbitte nutze diesen Link:\n${resetLink}\n\nGültig: 30 Minuten.\n`);
    await auditLog('reset.mail.sent', { email, ip });

    res.status(200).json({ ok:true, redirect:'/reset.html?sent=1' });
  } catch (err) {
    console.error(err); res.status(500).send('Internal error');
  }
});

// ---------- RESET: Token validieren ----------
app.get('/reset/validate', resetLimiter, async (req, res) => {
  try {
    const email = String(req.query.email || '').trim().toLowerCase();
    const token = String(req.query.token || '').trim();
    if (!email || !token) return res.status(400).json({ ok:false, error:'missing_parameters' });

    const tokens = await readJSON(TOKENS_FILE, []);
    const hit = tokens.find(t => t.email===email && t.token===token);
    if (!hit)                    return res.status(400).json({ ok:false, error:'invalid_token' });
    if (hit.used)                return res.status(400).json({ ok:false, error:'token_used' });
    if (Date.now() > hit.expiresAt) return res.status(400).json({ ok:false, error:'token_expired' });

    res.status(200).json({ ok:true });
  } catch (err) {
    console.error(err); res.status(500).json({ ok:false, error:'server_error' });
  }
});

// ---------- RESET: Passwort setzen (PBKDF2) ----------
app.post('/reset/confirm', resetLimiter, async (req, res) => {
  try {
    const ip   = getClientIP(req);
    const email= String(req.body.email || '').trim().toLowerCase();
    const token= String(req.body.token || '').trim();
    const firstname = String(req.body.firstname || req.body.firstName || '').trim();
    const lastname  = String(req.body.lastname  || req.body.lastName  || '').trim();
    const password  = String(req.body.password || '');
    if (!email || !token || !firstname || !lastname || !password) return res.status(400).json({ ok:false, error:'missing_parameters' });

    const tokens = await readJSON(TOKENS_FILE, []);
    const idx = tokens.findIndex(t => t.email===email && t.token===token);
    if (idx === -1)                 return res.status(400).json({ ok:false, error:'invalid_token' });
    const t = tokens[idx];
    if (t.used)                     return res.status(400).json({ ok:false, error:'token_used' });
    if (Date.now() > t.expiresAt)   return res.status(400).json({ ok:false, error:'token_expired' });

    if (!validatePasswordPolicy(password)) {
      return res.status(422).json({ ok:false, error:'weak_password', policy:'min 10 chars, upper+lower, and digit or special' });
    }

    const pwRec = createPasswordRecord(password);
    const users = await readJSON(USERS_FILE, []);
    const uIdx = users.findIndex(u => (u.email || '').toLowerCase() === email);
    const nowISO = new Date().toISOString();
    if (uIdx === -1) {
      users.push({ email, username:(email.split('@')[0]||'').toLowerCase(), ...pwRec, createdAt:nowISO, updatedAt:nowISO });
    } else {
      users[uIdx] = { ...users[uIdx], ...pwRec, updatedAt:nowISO };
    }
    await writeJSON(USERS_FILE, users);

    tokens[idx].used = true; await writeJSON(TOKENS_FILE, tokens);
    await auditLog('reset.confirm', { email, firstname, lastname, ip });

    res.status(200).json({ ok:true, redirect:'/login.html?reset=1' });
  } catch (err) {
    console.error(err); res.status(500).json({ ok:false, error:'server_error' });
  }
});

// ---------- ROOT & NOT FOUND ----------
app.get('/', (req, res) => { res.status(200).send('Hotel-Dashboard OK'); });
app.use((req, res) => { res.status(404).send('Not Found'); });

// ---------- ADMIN: STATUS ----------
app.get('/admin/status', async (req, res) => {
  try {
    const uptime = process.uptime();
    const fmtUptime = secs => {
      const h = Math.floor(secs/3600), m = Math.floor((secs%3600)/60), s = Math.floor(secs%60);
      return `${h}h ${m}m ${s}s`;
    };

    // Git-Infos
    const git = await new Promise(resolve => {
      execFile('bash', ['-lc',
        `cd "${REPO_DIR}" && \
         BR=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '-') && \
         LAST="$(git log -1 --pretty='%h %ci %s' 2>/dev/null || echo '-')"; \
         echo "$BR|$LAST"`
      ], { timeout: 4000 }, (err, stdout) => {
        if (err) return resolve({ ok:false });
        const [branch,last] = (stdout.trim().split('|').concat(['',''])).slice(0,2);
        resolve({ ok:true, branch, last });
      });
    });

    // Dienste (Beispiel: git-auto-push)
    const svc = await new Promise(resolve => {
      execFile('bash', ['-lc',
        'systemctl --user is-active git-auto-push.service >/dev/null 2>&1 && echo "running" || echo "inactive"'
      ], { timeout:3000 }, (_e, stdout) => {
        const state = stdout.trim();
        resolve([{ name:'git-auto-push', ok:(state==='running'), detail:state }]);
      });
    });

    res.json({
      node: { port: PORT, pid: process.pid, uptime: fmtUptime(uptime), ok:true },
      proxy:{ kind: 'Apache/Nginx (Proxy)', ok: true },
      git,
      services: svc
    });
  } catch (e) {
    res.status(500).json({ ok:false, error:'agent_failed' });
  }
});

// ---------- ADMIN: ACTIONS (POST) ----------
// Nur lokale Aufrufe zulassen (optional, hier soft check)
function isLocal(req){
  const ip = (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').toString();
  return ip.includes('127.0.0.1') || ip.includes('::1') || ip.startsWith('192.168.') || ip.startsWith('10.');
}

app.post('/admin/git/pull', (req, res) => {
  if (!isLocal(req)) return res.status(403).end();
  execFile('bash', ['-lc', `cd "${REPO_DIR}" && git pull --rebase --autostash origin main`], { timeout: 20000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr||'pull failed');
    res.status(200).send(stdout||'OK');
  });
});
app.post('/admin/git/push', (req, res) => {
  if (!isLocal(req)) return res.status(403).end();
  execFile('bash', ['-lc', `cd "${REPO_DIR}" && git add -A && (git diff --cached --quiet || git commit -m "dashboard push") && git push origin HEAD:main`], { timeout: 20000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr||'push failed');
    res.status(200).send(stdout||'OK');
  });
});
app.post('/admin/services/restart', (req, res) => {
  if (!isLocal(req)) return res.status(403).end();
  const name = String(req.query.name||'').trim();
  if (!name) return res.status(400).send('name required');
  execFile('bash', ['-lc', `systemctl --user restart ${name}.service`], { timeout: 15000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr||'restart failed');
    res.status(200).send(stdout||'OK');
  });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`Hotel-Dashboard listening on ${PORT}`);
});
