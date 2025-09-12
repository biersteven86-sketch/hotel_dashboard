/**
 * Admin-Status-Route für Hotel-Dashboard
 * Pfad: GET /admin/status
 * Liefert: Node/OS/Git, Dienste, Ports, Proxy-Checks und Express-Routen.
 */
const os = require('os');
const fs = require('fs');
const { execSync } = require('child_process');
const express = require('express');
const http = require('http');

function safeExec(cmd, opts = {}) {
  try { return execSync(cmd, { encoding: 'utf8', stdio: ['ignore','pipe','ignore'], ...opts }).trim(); }
  catch { return ''; }
}

function listExpressRoutes(app) {
  const out = [];
  const stack = (app && app._router && app._router.stack) ? app._router.stack : [];
  const walk = (layer, prefix='') => {
    if (layer.route && layer.route.path) {
      const methods = Object.keys(layer.route.methods).map(m => m.toUpperCase()).join(',');
      out.push(`${methods.padEnd(7)} ${prefix}${layer.route.path}`);
    } else if (layer.name === 'router' && layer.handle && layer.handle.stack) {
      const newPrefix = layer.regexp && layer.regexp.fast_slash ? prefix : (layer.regexp?.toString().match(/\\\/([A-Za-z0-9_\-:]+)/)?.[1] ? prefix + '/' + layer.regexp.toString().match(/\\\/([A-Za-z0-9_\-:]+)/)[1] : prefix);
      for (const l of layer.handle.stack) walk(l, newPrefix);
    }
  };
  for (const l of stack) walk(l, '');
  return Array.from(new Set(out)).sort();
}

function parsePorts() {
  // Fallback: ss kann fehlen auf sehr alten Systemen, daher tolerant
  const raw = safeExec("ss -tulpn 2>/dev/null | head -n 200");
  if (!raw) return [];
  return raw.split('\n').slice(1).filter(Boolean).map(l => l.replace(/\s+/g,' ').trim());
}

async function httpCheck(url, { method='GET', headers={}, timeout=2500 } = {}) {
  return new Promise((resolve) => {
    const req = http.request(url, { method, headers, timeout }, (res) => {
      resolve({ ok: res.statusCode && res.statusCode < 500, status: res.statusCode });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok:false, status:0 }); });
    req.on('error', () => resolve({ ok:false, status:0 }) );
    req.end();
  });
}

module.exports = function buildAdminStatusRouter(app){
  const router = express.Router();

  router.get('/', async (req,res) => {
    // Node / OS
    const node = {
      version: process.version,
      pid: process.pid,
      uptime: `${Math.floor(process.uptime())}s`,
      port: process.env.PORT || null,
    };
    const osInfo = {
      user: (os.userInfo().username || ''),
      cwd: process.cwd(),
      load: os.loadavg().map(n => Number(n.toFixed(2))),
      mem: `${Math.round((os.totalmem()-os.freemem())/1024/1024)}MB / ${Math.round(os.totalmem()/1024/1024)}MB`,
      platform: `${os.platform()} ${os.release()}`,
      arch: os.arch(),
    };

    // Git Infos (best effort)
    const git = {
      branch: safeExec('git rev-parse --abbrev-ref HEAD', { cwd: process.cwd() }) || '—',
      last: safeExec('git log -1 --pretty="%h %ad %s" --date=iso', { cwd: process.cwd() }) || '—',
      info: []
    };
    const remote = safeExec('git remote -v', { cwd: process.cwd() });
    if (remote) git.info.push(...remote.split('\n').slice(0,4));

    // Dienste (Beispiele, ergänzbar)
    const services = [];
    // Eigene Node-App (wir gehen davon aus, dass diese Route in der App läuft = OK)
    services.push({ name:'Node App', detail:'Express', ok:true });

    // Proxy-Reachability (Host-Header lokal gegen 127.0.0.1:3011; Port ggf. anpassen)
    const proxyChecks = [];
    const PORT_LOCAL = Number(process.env.PORT) || 3011;
    const hostHeader = process.env.DOMAIN || 'hotel-dashboard.de';

    // Basis-Checks
    const hc = await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/health`);
    proxyChecks.push(`GET 127.0.0.1:${PORT_LOCAL}/health -> ${hc.status}`);

    // Host-Header-Test (Apache/Nginx Proxy passt durch?)
    const rr = await new Promise((resolve) => {
      const req = http.request(
        { host:'127.0.0.1', port:PORT_LOCAL, path:'/', method:'GET', headers: { Host: hostHeader }, timeout: 2500 },
        (r) => resolve({ ok: r.statusCode && r.statusCode < 500, status:r.statusCode })
      );
      req.on('timeout', () => { req.destroy(); resolve({ ok:false, status:0 }); });
      req.on('error', () => resolve({ ok:false, status:0 }) );
      req.end();
    });
    proxyChecks.push(`GET 127.0.0.1:${PORT_LOCAL}/ (Host: ${hostHeader}) -> ${rr.status || 0}`);

    // Offene Ports
    const net = { ports: parsePorts() };

    // Express-Routen
    const routes = listExpressRoutes(app);

    // Session/Paths kleine Probes (nur Status, keine Daten)
    const probes = {
      login: await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/login`),
      reset: await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/reset`),
      session: await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/session/remaining`)
    };

    // WARN/OK-Heuristik für Dienste
    if (!hc.ok) services.push({ name:'Health', detail:'/health', ok:false });
    if (![200,204,302].includes((probes.login.status||0))) services.push({ name:'Login', detail:'/login', ok:false });
    if (![200,204,302].includes((probes.reset.status||0))) services.push({ name:'Reset', detail:'/reset', ok:false });

    res.json({
      node,
      os: osInfo,
      git,
      services,
      net,
      proxy: { checks: proxyChecks },
      routes
    });
  });

  return router;
};
