
// server.js — Hotel-Dashboard (vollständig, stabil, ohne Ibelsa)
// Apache → Proxy → Node (PORT 3011). Struktur wie besprochen beibehalten.
// Root leitet ausschließlich auf /index. Login/Reset/Guards/Static beibehalten.
// Enthält Admin-Statusroute /admin/status für Index-Übersicht.

'use strict';

require('dotenv').config({ quiet: true });

const express    = require('express');
const path       = require('path');
const fs         = require('fs');
const os         = require('os');
const crypto     = require('crypto');
const session    = require('express-session');
const rateLimit  = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { execFile } = require('child_process');

const app  = express();
const PORT = parseInt(process.env.PORT || '3011', 10);

// ===== Pfade =====
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

// ===== Helpers: JSON-Dateien =====
function loadJSON(p, def){ try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return def; } }
function saveJSON(p, obj){ fs.writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8'); }
function ensureUsers(){
  const j = loadJSON(usersPath, { users: [] });
  if (!Array.isArray(j.users)) j.users = [];
  saveJSON(usersPath, j);
}
function ensureTokens(){
  const j = loadJSON(tokensPath, { tokens: [] });
  if (!Array.isArray(j.tokens)) j.tokens = [];
  saveJSON(tokensPath, j);
}
ensureUsers(); ensureTokens();

// ===== Passwort (PBKDF2) =====
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')){
  const iterations = 310000, keylen = 32, digest = 'sha256';
  const hash = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
  return { algo: `pbkdf2:${digest}:${iterations}`, salt, hash };
}
function verifyPassword(password, user){
  if (!user?.passHash || !user?.passSalt) return false;
  const parts = String(user.passAlgo || '').split(':');
  const digest = parts[1] || 'sha256';
  const iterations = Number(parts[2] || 310000);
  const test = crypto.pbkdf2Sync(password, user.passSalt, iterations, 32, digest).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(test, 'hex'), Buffer.from(user.passHash, 'hex'));
}
function validatePasswordPolicy(p){
  return Boolean(p && p.length >= 10 && /[A-Z]/.test(p) && /[a-z]/.test(p) && (/\d/.test(p) || /[^A-Za-z0-9]/.test(p)));
}

// ===== Express Basics =====
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(publicDir, { index: false, extensions: ['html'] }));

// ===== Session (Idle-Timeout) =====
const IDLE_MS = Number(process.env.SESSION_IDLE_MS || 5*60*1000);
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: IDLE_MS }
}));

// ===== No-Store Helper =====
function setNoStore(res){
  res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma','no-cache');
  res.setHeader('Expires','0');
  res.setHeader('Surrogate-Control','no-store');
}

// ===== Offene Pfade & Assets =====
const assetRE = /\.(?:png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?)$/i;
const OPEN_PATHS = new Set([
  '/', '/health',
  '/login', '/login.html',
  '/reset', '/reset.html',
  '/reset/validate', '/reset/confirm',
  '/session/remaining',
  '/HD-Logo.png','/Hotel-Dashboard-Schriftzug.png',
  '/hotel-dashboard-bg.jpg','/Hotel-Dashboard-hintergrund.jpg','/Hotel-Dashboard-hintergrund 3.jpg'
]);

// ===== Aktivität & Timeout =====
app.use((req, res, next) => {
  const now = Date.now();
  const isAsset = assetRE.test(req.path);
  const isOpen  = OPEN_PATHS.has(req.path);
  const passive = isAsset || isOpen || req.path === '/session/remaining';

  if (req.session && req.session.user){
    const last = Number(req.session.lastActivity || 0);
    if (last && (now - last) > IDLE_MS){
      return req.session.destroy(() => {
        res.clearCookie('connect.sid', { httpOnly: true, sameSite:'lax', secure:false });
        return res.redirect('/login?timeout=1');
      });
    }
    if (!passive) req.session.lastActivity = now;
  }
  next();
});

// ===== Guards =====
app.use((req, res, next) => {
  if (assetRE.test(req.path)) return next();
  if (OPEN_PATHS.has(req.path)) return next();
  if (req.path.startsWith('/public/')) return next();
  if (req.session && req.session.user){ setNoStore(res); return next(); }
  return res.redirect('/login');
});

// ===== Root nur → /index =====
app.get('/', (_req, res) => res.redirect('/index'));

// .html direkt blocken außer whitelist
app.use((req, res, next) => {
  if (req.path.endsWith('.html') && !/^\/(login|reset|index|dashboard)\.html$/i.test(req.path)){
    return res.redirect('/login');
  }
  next();
});

// ===== Session Remaining =====
app.get('/session/remaining', (req, res) => {
  const now = Date.now();
  let remaining = 0;
  if (req.session && req.session.user){
    const last = Number(req.session.lastActivity || 0);
    remaining = Math.max(0, (last ? (IDLE_MS - (now - last)) : IDLE_MS));
    setNoStore(res);
  } else {
    res.setHeader('Cache-Control','no-store');
  }
  res.json({ ok:true, remaining, idleMs: IDLE_MS });
});

// ===== Login/Reset Seiten =====
app.get ('/login',  (_req, res) => res.sendFile('login.html',  { root: publicDir }));
app.head('/login',  (_req, res) => res.sendStatus(200));
app.get ('/reset',  (_req, res) => res.sendFile('reset.html',  { root: publicDir }));
app.head('/reset',  (_req, res) => res.sendStatus(200));

// ===== Reset-Flow =====
app.post('/reset', async (req, res) => {
  try{
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).type('text').send('E-Mail fehlt');

    const token = Math.random().toString(36).slice(2,10);
    const now   = Date.now();
    const exp   = now + 30*60*1000;

    const db = loadJSON(tokensPath, { tokens: [] });
    db.tokens = Array.isArray(db.tokens) ? db.tokens : [];
    // alte Tokens für E-Mail invalidieren
    db.tokens = db.tokens.map(t => t.email===email ? { ...t, used:true } : t);
    db.tokens.push({ email, token, createdAt: now, expiresAt: exp, used:false });
    saveJSON(tokensPath, db);

    // Mail (optional, nur wenn SMTP vorhanden)
    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS){
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
        text: `Dein Code: ${token}\n\nOder Link: ${verifyUrl}\n(Gültig 30 Minuten)`
      });
    }

    res.type('text').send('Reset-Mail verschickt (falls konfiguriert).');
  }catch(err){
    console.error('reset error:', err && (err.stack || err));
    res.status(500).type('text').send('Fehler');
  }
});

app.get('/reset/validate', (req, res) => {
  const token = String(req.query.token||'').trim();
  const email = String(req.query.email||'').trim().toLowerCase();
  if (!token || !email) return res.status(400).json({ ok:false, msg:'token/email fehlt' });

  const db = loadJSON(tokensPath, { tokens: [] });
  const now = Date.now();
  const rec = (db.tokens||[]).find(t => t.email===email && t.token===token && !t.used && t.expiresAt>now);
  if (!rec) return res.status(404).json({ ok:false, msg:'ungültig oder abgelaufen' });
  res.json({ ok:true, msg:'valid' });
});
app.head('/reset/validate', (_req, res) => res.sendStatus(200));

app.post('/reset/confirm', (req, res) => {
  try{
    const token     = String(req.body.token || '').trim();
    const emailRaw  = String(req.body.email || '').trim();
    const email     = emailRaw.toLowerCase();
    const password  = String(req.body.password || '');
    const firstname = String(req.body.firstname || req.body.firstName || '').trim();
    const lastname  = String(req.body.lastname  || req.body.lastName  || '').trim();
    if (!token || !email || !password || !firstname || !lastname){
      return res.status(400).type('text').send('Pflichtfelder fehlen');
    }
    if (!validatePasswordPolicy(password)){
      return res.status(422).type('text').send('Passwort zu schwach');
    }

    // Token prüfen
    const db = loadJSON(tokensPath, { tokens: [] });
    const now = Date.now();
    const idx = (db.tokens||[]).findIndex(t => t.email===email && t.token===token && !t.used && t.expiresAt>now);
    if (idx === -1) return res.status(403).type('text').send('Token ungültig/abgelaufen');
    db.tokens[idx].used = true;
    saveJSON(tokensPath, db);

    // User setzen
    const ud = loadJSON(usersPath, { users: [] });
    const uIdx = ud.users.findIndex(u => (u.email||'').toLowerCase() === email);
    const { algo, salt, hash } = hashPassword(password);
    const username = emailRaw.split('@')[0];
    const nowISO = new Date().toISOString();
    if (uIdx === -1){
      ud.users.push({ email, username, firstname, lastname, passAlgo:algo, passSalt:salt, passHash:hash, createdAt:nowISO, updatedAt:nowISO });
    } else {
      ud.users[uIdx] = { ...ud.users[uIdx], firstname, lastname, passAlgo:algo, passSalt:salt, passHash:hash, updatedAt:nowISO };
    }
    saveJSON(usersPath, ud);

    // Audit
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
    fs.appendFileSync(auditLog, JSON.stringify({ ts:new Date().toISOString(), email, firstname, lastname, ip })+'\n');

    res.type('text').send('Passwort gesetzt');
  }catch(err){
    console.error('confirm error:', err && (err.stack || err));
    res.status(500).type('text').send('Fehler beim Setzen');
  }
});

// ===== Login / Logout =====
const loginLimiter = rateLimit({ windowMs: 5*60*1000, max: 50, standardHeaders:true, legacyHeaders:false });

app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const name = String(username || '').trim();
  const pass = String(password || '');

  const ud = loadJSON(usersPath, { users: [] });
  const nameLower = name.toLowerCase();
  const user = ud.users.find(u => (u.email && u.email.toLowerCase()===nameLower) || (u.username && u.username.toLowerCase()===nameLower));
  if (user && verifyPassword(pass, user)){
    req.session.user = name;
    req.session.lastActivity = Date.now();
    return res.redirect('/after-login');
  }

  const { DASH_USER='', DASH_PASS='', ADMIN_USER='', ADMIN_PASS='' } = process.env;
  const ok = (name===DASH_USER && pass===DASH_PASS) || (name===ADMIN_USER && pass===ADMIN_PASS);

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

app.get('/after-login', (req, res) => {
  const u = (req.session && req.session.user) ? String(req.session.user) : '';
  const adminUser = (process.env.ADMIN_USER || 'admin').toLowerCase();
  if (u && u.toLowerCase() === adminUser){ setNoStore(res); return res.redirect('/index'); }
  setNoStore(res); return res.redirect('/dashboard');
});

// ===== Geschützte Seiten =====
function requireAuth(req, res, next){
  if (req.session && req.session.user){ setNoStore(res); return next(); }
  return res.redirect('/login');
}
app.get('/index',     requireAuth, (_req, res) => res.sendFile('index.html',     { root: publicDir }));
app.get('/dashboard', requireAuth, (_req, res) => res.sendFile('dashboard.html', { root: publicDir }));

// ===== Health =====
app.get ('/health', (_req, res) => res.type('text').send('OK'));
app.head('/health', (_req, res) => res.sendStatus(200));

// ===== Admin-Status für Index =====
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
    execFile('bash',['-lc',cmd],{timeout:4000},(err,stdout,stderr)=>{
      if (err) return resolve({ ok:false, out:String(stderr||stdout||'').trim() });
      resolve({ ok:true, out:String(stdout||'').trim() });
    });
  });
}
app.get('/admin/status', requireAuth, async (_req, res) => {
  try{
    const mem = (process.memoryUsage().rss/1024/1024).toFixed(1)+' MB RSS';
    const la = os.loadavg().map(x=>x.toFixed(2));
    const user = (process.env.SUDO_USER || process.env.USER || process.env.LOGNAME || 'n/a');
    const repoDir = path.resolve('/home/steven/hotel_dashboard');
    const g1 = await sh(`cd "${repoDir}" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "-"`);
    const g2 = await sh(`cd "${repoDir}" && git log -1 --pretty='%h %ci %s' 2>/dev/null || echo "-"`);
    const g3 = await sh(`cd "${repoDir}" && git status -sb 2>/dev/null || echo "-"`);
    const s1 = await sh('systemctl --user is-active git-auto-push.service 2>/dev/null || echo inactive');
    const s2 = await sh('systemctl is-active apache2 2>/dev/null || echo inactive');
    const s3 = await sh('systemctl is-active nginx 2>/dev/null || echo inactive');
    const p1 = await sh(`ss -tulpn | awk 'NR==1 || /:(80|443|3000|3011)\\b/'`);
    const pr1 = await sh(`curl -s -I -H "Host: admin.adminheim-rottweil.de" http://127.0.0.1/ | sed -n '1,5p'`);
    const pr2 = await sh(`curl -s -I -H "Host: info.adminheim-rottweil.de"  http://127.0.0.1/ | sed -n '1,5p'`);
    res.json({
      node:{ port:PORT, pid:process.pid, uptime:fmtUptime(process.uptime()), version:process.version },
      os:{ load:la, mem, user, cwd:process.cwd() },
      git:{ branch:g1.out, last:g2.out, info:g3.out.split('\n').slice(0,10) },
      services:[
        { name:'git-auto-push', ok:(s1.out.trim()==='active'), detail:s1.out.trim() },
        { name:'apache2',       ok:(s2.out.trim()==='active'), detail:s2.out.trim() },
        { name:'nginx',         ok:(s3.out.trim()==='active'), detail:s3.out.trim() }
      ],
      net:{ ports:(p1.out||'').split('\n').slice(0,40) },
      proxy:{ checks:['admin.adminheim-rottweil.de →', ...(pr1.out||'').split('\n').slice(0,5), 'info.adminheim-rottweil.de →', ...(pr2.out||'').split('\n').slice(0,5)] },
      routes: listRoutes(app)
    });
  }catch(e){
    console.error('status error:', e);
    res.status(500).json({ ok:false, error:'status_failed' });
  }
});

// --- ADMIN STATUS (nur hinzufügen, nichts anderes ändern) ---
const os = require('os');
const { execSync } = require('child_process');

function formatBytes(n){
  const u=['B','KB','MB','GB','TB']; let i=0, f=n;
  while(f>1024 && i<u.length-1){ f/=1024; i++; }
  return `${f.toFixed(1)} ${u[i]}`;
}
function listRoutes(app){
  const out = [];
  function walker(layer, prefix=''){
    if(layer.route && layer.route.path){
      const methods = Object.keys(layer.route.methods).map(m=>m.toUpperCase()).join(',');
      out.push(`${methods.padEnd(7)} ${prefix}${layer.route.path}`);
    }else if(layer.name==='router' && layer.handle.stack){
      const newPrefix = layer.regexp && layer.regexp.fast_slash ? prefix : (prefix || '');
      layer.handle.stack.forEach(l=>walker(l, newPrefix));
    }else if(layer.handle && layer.handle.stack){
      layer.handle.stack.forEach(l=>walker(l, prefix));
    }
  }
  if(app && app._router && app._router.stack) app._router.stack.forEach(l=>walker(l,''));
  return out.sort();
}

app.get('/admin/status', async (req, res) => {
  try{
    // Node / OS
    const memTotal = os.totalmem(), memFree = os.freemem();
    const payload = {
      node: {
        port: process.env.PORT || 3000,
        pid: process.pid,
        version: process.version,
        uptime: `${Math.floor(process.uptime())}s`,
      },
      os: {
        user: os.userInfo().username,
        cwd: process.cwd(),
        load: os.loadavg().map(v=>v.toFixed(2)),
        mem: `${formatBytes(memTotal - memFree)} / ${formatBytes(memTotal)}`,
      },
      git: {},
      services: [],
      net: { ports: [] },
      proxy: { checks: [] },
      routes: listRoutes(req.app),
    };

    // Git-Infos (best effort)
    try{
      const branch = execSync('git rev-parse --abbrev-ref HEAD',{stdio:['ignore','pipe','ignore']}).toString().trim();
      const last   = execSync('git log -1 --pretty="%h · %s · %ci"',{stdio:['ignore','pipe','ignore']}).toString().trim();
      const stat   = execSync('git status -sb',{stdio:['ignore','pipe','ignore']}).toString().trim().split('\n');
      payload.git = { branch, last, info: stat };
    }catch{ payload.git = { branch:'-', last:'-', info:['(kein Git verfügbar)'] }; }

    // Offene Ports (Kurzansicht) – best effort
    try{
      const ssOut = execSync('ss -ltnp | head -n 30',{stdio:['ignore','pipe','ignore']}).toString().split('\n').filter(Boolean);
      payload.net.ports = ssOut;
    }catch{ payload.net.ports = ['(ss nicht verfügbar)']; }

    // Proxy-Reachability mit verschiedenen Host-Headern (nur Anzeige)
    const hosts = ['localhost:3000','127.0.0.1:3000'];
    payload.proxy.checks = hosts.map(h => `Host: ${h} → GET /`);

    // Dienste (Beispiele – passe bei Bedarf an)
    payload.services = [
      { name: 'Node/Express', detail: `PID ${process.pid}`, ok: true },
      { name: 'Sessions', detail: 'Cookie/Session', ok: true, warn: false },
      { name: 'Git Auto', detail: 'Webhook/Autopush (manuell prüfen)', ok: true, warn: true }
    ];

    res.json(payload);
  }catch(e){
    res.status(500).json({ error: 'status_failed', message: String(e) });
  }
});


// ===== 404 =====
app.use((_req,res)=> res.status(404).sendFile('login.html',{root: publicDir}));

// ===== Start =====
app.listen(PORT, () => {
  console.log('Hotel-Dashboard läuft auf Port', PORT);
  console.log('ROOT      :', ROOT);
  console.log('publicDir :', publicDir);
  console.log('users.json:', usersPath);
  console.log('tokens    :', tokensPath);
  console.log('audit log :', auditLog);
  console.log('session idle(ms):', IDLE_MS);
});
// --- ADMIN STATUS (nur hinzufügen, nichts anderes ändern) ---
const os = require('os');
const { execSync } = require('child_process');

function formatBytes(n){ const u=['B','KB','MB','GB','TB']; let i=0,f=n; while(f>1024&&i<u.length-1){f/=1024;i++;} return `${f.toFixed(1)} ${u[i]}`; }
function listRoutes(app){
  const out=[];
  function walk(layer){
    if(layer.route && layer.route.path){
      const methods=Object.keys(layer.route.methods).map(m=>m.toUpperCase()).join(',');
      out.push(`${methods.padEnd(7)} ${layer.route.path}`);
    }else if(layer.name==='router' && layer.handle && layer.handle.stack){
      layer.handle.stack.forEach(walk);
    }else if(layer.handle && layer.handle.stack){
      layer.handle.stack.forEach(walk);
    }
  }
  if(app && app._router && app._router.stack) app._router.stack.forEach(walk);
  return out.sort();
}

app.get('/admin/status', (req,res)=>{
  try{
    const memTotal=os.totalmem(), memFree=os.freemem();
    const payload={
      node:{ port:process.env.PORT||3000, pid:process.pid, version:process.version, uptime:`${Math.floor(process.uptime())}s` },
      os:{ user:os.userInfo().username, cwd:process.cwd(), load:os.loadavg().map(v=>v.toFixed(2)), mem:`${formatBytes(memTotal-memFree)} / ${formatBytes(memTotal)}` },
      git:{}, services:[], net:{ports:[]}, proxy:{checks:[]}, routes:listRoutes(req.app)
    };
    try{
      payload.git.branch=execSync('git rev-parse --abbrev-ref HEAD',{stdio:['ignore','pipe','ignore']}).toString().trim();
      payload.git.last=execSync('git log -1 --pretty="%h · %s · %ci"',{stdio:['ignore','pipe','ignore']}).toString().trim();
      payload.git.info=execSync('git status -sb',{stdio:['ignore','pipe','ignore']}).toString().trim().split('\n');
    }catch{ payload.git={branch:'-',last:'-',info:['(kein Git verfügbar)']}; }
    try{
      payload.net.ports=execSync('ss -ltnp | head -n 30',{stdio:['ignore','pipe','ignore']}).toString().split('\n').filter(Boolean);
    }catch{ payload.net.ports=['(ss nicht verfügbar)']; }
    payload.proxy.checks=['localhost:3000','127.0.0.1:3000'].map(h=>`Host: ${h} → GET /`);
    payload.services=[ {name:'Node/Express',detail:`PID ${process.pid}`,ok:true} ];
    res.json(payload);
  }catch(e){ res.status(500).json({error:'status_failed',message:String(e)}); }
});
