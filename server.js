// server.js — Hotel-Dashboard (stabil, ohne Ibelsa)
// Port/Proxy: Apache → Node (Port 3011)
// Root leitet nur auf /index, Struktur & Flow unverändert

'use strict';

const express    = require('express');
const path       = require('path');
const fs         = require('fs');
const os         = require('os');
const crypto     = require('crypto');
const session    = require('express-session');
const rateLimit  = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { execFile } = require('child_process');

require('dotenv').config({ quiet: true });

const app  = express();
// In deinem Setup läuft Node hinter Apache auf 3011
const PORT = parseInt(process.env.PORT || '3011', 10);

// ====== Verzeichnisse ======
const ROOT        = process.env.HD_ROOT ? path.resolve(process.env.HD_ROOT) : path.resolve(__dirname);
const publicDir   = path.join(ROOT, 'public');
const dataDir     = path.join(ROOT, 'data');
const authDir     = path.join(dataDir, 'auth');
const usersPath   = path.join(dataDir, 'users.json');
const tokensPath  = path.join(authDir, 'reset.db.json');
const auditLog    = path.join(authDir, 'reset_audit.log');

fs.mkdirSync(publicDir, { recursive: true });
fs.mkdirSync(dataDir,   { recursive: true });
fs.mkdirSync(authDir,   { recursive: true });

// ====== Helpers: Users & Tokens ======
function loadJSON(p, def){ try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return def; } }
function saveJSON(p, obj){ fs.writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8'); }

function loadUsers(){
  const j = loadJSON(usersPath, { users: [] });
  if (!Array.isArray(j.users)) j.users = [];
  return j;
}
function saveUsers(j){ saveJSON(usersPath, { users: Array.isArray(j.users) ? j.users : [] }); }

function loadTokens(){
  const j = loadJSON(tokensPath, { tokens: [] });
  if (!Array.isArray(j.tokens)) j.tokens = [];
  return j;
}
function saveTokens(j){ saveJSON(tokensPath, { tokens: Array.isArray(j.tokens) ? j.tokens : [] }); }
function purgeExpiredTokens(db){
  const now = Date.now();
  db.tokens = db.tokens.filter(t => !t.used && t.expiresAt > now);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')){
  const iterations = 310000, keylen = 32, digest = 'sha256';
  const hash = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
  return { algo: `pbkdf2:${digest}:${iterations}`, salt, hash };
}
function verifyPassword(password, user){
  if (!user?.passHash || !user?.passSalt) return false;
  const parts = String(user.passAlgo || '').split(':'); // pbkdf2:sha256:310000
  const iterations = Number(parts[2] || 310000);
  const digest = parts[1] || 'sha256';
  const test = crypto.pbkdf2Sync(password, user.passSalt, iterations, 32, digest).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(test, 'hex'), Buffer.from(user.passHash, 'hex'));
}

// ====== Express Basics ======
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ====== Sessions ======
const IDLE_MS = Number(process.env.SESSION_IDLE_MS || 5 * 60 * 1000); // 5 Minuten

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,        // hinter TLS-Proxy ggf. true setzen
    maxAge: IDLE_MS
  }
}));

// ====== Static (keine Auto-Index-Auslieferung; wir steuern per Routen) ======
app.use(express.static(publicDir, { index: false, extensions: ['html'] }));

// ====== Cache-Control für geschützte Antworten ======
function setNoStore(res){
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
}

// ====== Offene Pfade & Assets ======
const assetRE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?)$/i;
const OPEN_PATHS = new Set([
  '/', '/health',
  '/login', '/login.html',
  '/reset', '/reset.html',
  '/reset/validate', '/reset/confirm',
  '/session/remaining',
  // erlaubte Assets
  '/HD-Logo.png',
  '/Hotel-Dashboard-Schriftzug.png',
  '/hotel-dashboard-bg.jpg',
  '/Hotel-Dashboard-hintergrund.jpg',
  '/Hotel-Dashboard-hintergrund 3.jpg'
]);

// ====== Aktivitäts-/Timeout-Check ======
app.use((req, res, next) => {
  const now = Date.now();
  const isAsset   = assetRE.test(req.path);
  const isOpen    = OPEN_PATHS.has(req.path);
  const isPassive = isAsset || isOpen || req.path === '/session/remaining';

  if (req.session && req.session.user) {
    const last = Number(req.session.lastActivity || 0);
    const expired = last && (now - last) > IDLE_MS;
    if (expired) {
      return req.session.destroy(() => {
        res.clearCookie('connect.sid', { httpOnly:true, sameSite:'lax', secure:false });
        return res.redirect('/login?timeout=1');
      });
    }
    if (!isPassive) req.session.lastActivity = now;
  }
  next();
});

// ====== Guards (alles außer offene Pfade/Assets braucht Login) ======
app.use((req, res, next) => {
  if (assetRE.test(req.path)) return next();
  if (OPEN_PATHS.has(req.path)) return next();
  if (req.path.startsWith('/public/')) return next();
  if (req.session && req.session.user) { setNoStore(res); return next(); }
  return res.redirect('/login');
});

// ====== Nur diese eine Root-Weiterleitung (deine Vorgabe) ======
app.get('/', (_req, res) => res.redirect('/index'));

// .html-Direktaufrufe blocken, außer explizit erlaubte Seiten
app.use((req, res, next) => {
  if (req.path.endsWith('.html') && !/^\/(login|reset|index|dashboard)\.html$/i.test(req.path)) {
    return res.redirect('/login');
  }
  next();
});

// ====== Session-Countdown ======
app.get('/session/remaining', (req, res) => {
  const now = Date.now();
  let remaining = 0;
  if (req.session && req.session.user) {
    const last = Number(req.session.lastActivity || 0);
    remaining = Math.max(0, (last ? (IDLE_MS - (now - last)) : IDLE_MS));
    setNoStore(res);
  } else {
    res.setHeader('Cache-Control', 'no-store');
  }
  res.json({ ok:true, remaining, idleMs: IDLE_MS });
});

// ====== Öffentlich: Login/Reset Seiten ======
app.get ('/login', (_req, res) => res.sendFile('login.html', { root: publicDir }));
app.head('/login', (_req, res) => res.sendStatus(200));

app.get ('/reset', (_req, res) => res.sendFile('reset.html', { root: publicDir }));
app.head('/reset', (_req, res) => res.sendStatus(200));

// ====== Reset-Flow ======
// Reset anstoßen: Token erzeugen + Mail
app.post('/reset', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).type('text').send('E-Mail fehlt');

    const token = Math.random().toString(36).slice(2, 10);
    const now   = Date.now();
    const exp   = now + 30 * 60 * 1000; // 30 Min

    const db = loadTokens();
    purgeExpiredTokens(db);
    db.tokens = db.tokens.filter(t => t.email !== email);
    db.tokens.push({ email, token, createdAt: now, expiresAt: exp, used: false });
    saveTokens(db);

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      tls: { rejectUnauthorized: false }
    });

    const appBase = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
    const verifyUrl = `${appBase}/reset?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;

    await transporter.sendMail({
      from: `"Passwort-Service" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Passwort zurücksetzen',
      text:
`Hallo,

wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten.
Dein Code lautet: ${token}

Oder klicke:
${verifyUrl}

Der Code ist 30 Minuten gültig.
Falls du das nicht warst, kannst du diese Nachricht ignorieren.`,
      html:
`<p>Hallo,</p>
<p>wir haben eine Anfrage zum Zurücksetzen deines Passworts erhalten.</p>
<p>Dein Code lautet: <b>${token}</b></p>
<p>Oder klicke: <a href="${verifyUrl}">${verifyUrl}</a></p>
<p>Der Code ist 30&nbsp;Minuten gültig.<br>Falls du das nicht warst, kannst du diese Nachricht ignorieren.</p>`
    });

    return res.type('text').send('Reset-Mail verschickt. Bitte Postfach prüfen.');
  } catch (err) {
    console.error('❌ Fehler /reset:', err && (err.stack || err));
    return res.status(500).type('text').send('Mailversand fehlgeschlagen');
  }
});

// Token prüfen (für UI-Vorprüfung)
app.get('/reset/validate', (req, res) => {
  const token = String(req.query.token || '').trim();
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!token || !email) return res.status(400).json({ ok:false, msg:'token/email fehlt' });

  const db = loadTokens();
  const now = Date.now();
  const rec = db.tokens.find(t => t.email === email && t.token === token && !t.used && t.expiresAt > now);
  if (!rec) return res.status(404).json({ ok:false, msg:'ungültig oder abgelaufen' });

  return res.json({ ok:true, msg:'valid' });
});
app.head('/reset/validate', (_req, res) => res.sendStatus(200));

// Passwort endgültig setzen
app.post('/reset/confirm', (req, res) => {
  try {
    const token     = String(req.body.token || '').trim();
    const emailRaw  = String(req.body.email || '').trim();
    const email     = emailRaw.toLowerCase();
    const password  = String(req.body.password || '');
    const firstname = String(req.body.firstname || req.body.firstName || '').trim();
    const lastname  = String(req.body.lastname  || req.body.lastName  || '').trim();

    if (!token || !email || !password || !firstname || !lastname) {
      return res.status(400).type('text').send('Pflichtfelder fehlen');
    }

    // Stärkeprüfung
    const strong = (
      password.length >= 10 &&
      /[A-Z]/.test(password) &&
      /[a-z]/.test(password) &&
      (/\d/.test(password) || /[^A-Za-z0-9]/.test(password))
    );
    if (!strong) return res.status(422).type('text').send('Passwort zu schwach');

    const db = loadTokens();
    const now = Date.now();
    const idx = db.tokens.findIndex(t => t.email === email && t.token === token && !t.used && t.expiresAt > now);
    if (idx === -1) return res.status(403).type('text').send('Token ungültig/abgelaufen');

    db.tokens[idx].used = true;
    purgeExpiredTokens(db);
    saveTokens(db);

    // Audit
    const audit = {
      ts: new Date().toISOString(),
      email,
      firstname,
      lastname,
      ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString()
    };
    fs.appendFileSync(auditLog, JSON.stringify(audit) + '\n');

    // User anlegen/aktualisieren
    const udb = loadUsers();
    const uIdx = udb.users.findIndex(u => (u.email || '').toLowerCase() === email);
    const { algo, salt, hash } = hashPassword(password);
    const username = emailRaw.split('@')[0];

    if (uIdx === -1) {
      udb.users.push({
        email,
        username,
        firstname,
        lastname,
        passAlgo: algo,
        passSalt: salt,
        passHash: hash,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });
    } else {
      udb.users[uIdx] = {
        ...udb.users[uIdx],
        firstname,
        lastname,
        passAlgo: algo,
        passSalt: salt,
        passHash: hash,
        updatedAt: new Date().toISOString()
      };
    }
    saveUsers(udb);

    return res.type('text').send('Passwort gesetzt');
  } catch (err) {
    console.error('❌ Fehler /reset/confirm:', err && (err.stack || err));
    return res.status(500).type('text').send('Fehler beim Setzen des Passworts');
  }
});

// ====== Login / Logout ======
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const name = String(username || '').trim();
  const pass = String(password || '');

  // 1) users.json
  const ud = loadUsers();
  const nameLower = name.toLowerCase();
  const user = ud.users.find(u =>
    (u.email && u.email.toLowerCase() === nameLower) ||
    (u.username && u.username.toLowerCase() === nameLower)
  );
  if (user && verifyPassword(pass, user)) {
    req.session.user = name;
    req.session.lastActivity = Date.now();
    return res.redirect('/after-login');
  }

  // 2) optionale .env-Fallbacks
  const {
    DASH_USER = '', DASH_PASS = '',
    ADMIN_USER = '', ADMIN_PASS = '',
    EXTRA_USER = '', EXTRA_PASS = ''
  } = process.env;

  const ok =
    (name === DASH_USER   && pass === DASH_PASS)   ||
    (name === ADMIN_USER  && pass === ADMIN_PASS)  ||
    (name === EXTRA_USER  && pass === EXTRA_PASS);

  if (!ok) return res.redirect('/login?err=1');

  req.session.user = name;
  req.session.lastActivity = Date.now();
  return res.redirect('/after-login');
});

app.get('/logout', (req, res) => {
  if (!req.session) return res.redirect('/login');
  req.session.destroy(() => {
    res.clearCookie('connect.sid', { httpOnly:true, sameSite:'lax', secure:false });
    return res.redirect('/login');
  });
});

// Nach Login verteilen (Admin → /index, andere → /dashboard)
app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser) {
    setNoStore(res);
    return res.redirect('/index');
  }
  setNoStore(res);
  return res.redirect('/dashboard');
});

// ====== Geschützte Seiten ======
function requireAuth(req, res, next){
  if (req.session && req.session.user) { setNoStore(res); return next(); }
  return res.redirect('/login');
}
app.get('/index',     requireAuth, (_req, res) => res.sendFile('index.html',     { root: publicDir }));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile('dashboard.html', { root: publicDir }));

// ====== Health ======
app.get ('/health', (_req, res) => res.type('text').send('OK'));
app.head('/health', (_req, res) => res.sendStatus(200));

// ====== Admin-Status (für Index-Übersicht; geschützt) ======
function fmtUptime(secs){ const h=Math.floor(secs/3600), m=Math.floor((secs%3600)/60), s=Math.floor(secs%60); return `${h}h ${m}m ${s}s`; }
function listRoutes(app){
  try{
    const out=[];
    app._router.stack.forEach(l=>{
      if (l.route && l.route.path){
        const methods = Object.keys(l.route.methods||{}).filter(k=>l.route.methods[k]).join(',').toUpperCase();
        out.push(`${methods.padEnd(10)} ${l.route.path}`);
      } else if (l.name==='router' && l.handle && l.handle.stack){
        l.handle.stack.forEach(r=>{
          if (r.route && r.route.path){
            const methods = Object.keys(r.route.methods||{}).filter(k=>r.route.methods[k]).join(',').toUpperCase();
            out.push(`${methods.padEnd(10)} ${r.route.path}`);
          }
        });
      }
    });
    return out.sort();
  }catch{ return []; }
}
function sh(cmd){
  return new Promise(resolve=>{
    execFile('bash', ['-lc', cmd], {timeout:4000}, (err, stdout, stderr)=>{
      if (err) return resolve({ ok:false, out:String(stderr||stdout||'').trim() });
      resolve({ ok:true, out:String(stdout||'').trim() });
    });
  });
}

app.get('/admin/status', requireAuth, async (_req, res) => {
  try{
    const memUsed = process.memoryUsage();
    const memMB = (memUsed.rss/1024/1024).toFixed(1) + ' MB RSS';
    const la = os.loadavg().map(x=>x.toFixed(2));
    const user = (process.env.SUDO_USER || process.env.USER || process.env.LOGNAME || 'n/a');

    const REPO_DIR = path.resolve('/home/steven/hotel_dashboard');
    const g1 = await sh(`cd "${REPO_DIR}" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "-"`);
    const g2 = await sh(`cd "${REPO_DIR}" && git log -1 --pretty='%h %ci %s' 2>/dev/null || echo "-"`);
    const g3 = await sh(`cd "${REPO_DIR}" && git status -sb 2>/dev/null || echo "-"`);

    const s1 = await sh('systemctl --user is-active git-auto-push.service 2>/dev/null || echo inactive');
    const s2 = await sh('systemctl is-active apache2 2>/dev/null || echo inactive');
    const s3 = await sh('systemctl is-active nginx 2>/dev/null || echo inactive');

    const p1 = await sh(`ss -tulpn | awk 'NR==1 || /:(80|443|3000|3011)\\b/'`);

    const pr1 = await sh(`curl -s -I -H "Host: admin.adminheim-rottweil.de" http://127.0.0.1/ | sed -n '1,5p'`);
    const pr2 = await sh(`curl -s -I -H "Host: info.adminheim-rottweil.de"  http://127.0.0.1/ | sed -n '1,5p'`);

    res.json({
      node:{
        port: PORT,
        pid: process.pid,
        uptime: fmtUptime(process.uptime()),
        version: process.version
      },
      os:{
        load: la,
        mem: memMB,
        user,
        cwd: process.cwd()
      },
      git:{
        branch: g1.out,
        last:   g2.out,
        info:   g3.out.split('\n').slice(0,10)
      },
      services:[
        { name:'git-auto-push', ok:(s1.out.trim()==='active'), detail:s1.out.trim() },
        { name:'apache2',       ok:(s2.out.trim()==='active'), detail:s2.out.trim() },
        { name:'nginx',         ok:(s3.out.trim()==='active'), detail:s3.out.trim() }
      ],
      net:{   ports: (p1.out || '').split('\n').slice(0,40) },
      proxy:{ checks: ['admin.adminheim-rottweil.de →', ...(pr1.out||'').split('\n').slice(0,5), 'info.adminheim-rottweil.de →', ...(pr2.out||'').split('\n').slice(0,5)] },
      routes: listRoutes(app)
    });
  }catch(e){
    console.error('status error:', e);
    res.status(500).json({ ok:false, error:'status_failed' });
  }
});

// ====== 404 → Login (Assets fängt static oben ab) ======
app.use((_req, res) => res.status(404).sendFile('login.html', { root: publicDir }));

// ====== Start ======
app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  console.log('ROOT      :', ROOT);
  console.log('publicDir :', publicDir);
  console.log('users.json:', usersPath);
  console.log('tokens    :', tokensPath);
  console.log('audit log :', auditLog);
  console.log('session idle(ms):', IDLE_MS);
});
