/**
 * Admin-Status-Route für Hotel-Dashboard
 * GET /admin/status
 * Liefert: Node/OS/Git, Dienste, Ports, Proxy-Checks und Express-Routen.
 */
const os = require('os');
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
      for (const l of layer.handle.stack) walk(l, prefix);
    }
  };
  for (const l of stack) walk(l, '');
  return Array.from(new Set(out)).sort();
}

function parsePorts() {
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

  // Status JSON
  router.get('/', async (_req,res) => {
    const node = {
      version: process.version,
      pid: process.pid,
      uptime: `${Math.floor(process.uptime())}s`,
      port: Number(process.env.PORT) || null,
    };
    const osInfo = {
      user: (os.userInfo().username || ''),
      cwd: process.cwd(),
      load: os.loadavg().map(n => Number(n.toFixed(2))),
      mem: `${Math.round((os.totalmem()-os.freemem())/1024/1024)}MB / ${Math.round(os.totalmem()/1024/1024)}MB`,
      platform: `${os.platform()} ${os.release()}`,
      arch: os.arch(),
    };

    const git = {
      branch: safeExec('git rev-parse --abbrev-ref HEAD', { cwd: process.cwd() }) || '—',
      last: safeExec('git log -1 --pretty="%h %ad %s" --date=iso', { cwd: process.cwd() }) || '—',
      info: []
    };
    const remote = safeExec('git remote -v', { cwd: process.cwd() });
    if (remote) git.info.push(...remote.split('\n').slice(0,4));

    const services = [{ name:'Node App', detail:'Express', ok:true }];

    const PORT_LOCAL = Number(process.env.PORT) || 3011;
    const hostHeader = process.env.DOMAIN || 'hotel-dashboard.de';

    const hc = await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/health`);
    const rr = await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/`, { headers: { Host: hostHeader } });

    const net = { ports: parsePorts() };
    const routes = listExpressRoutes(app);
    const proxyChecks = [
      `GET 127.0.0.1:${PORT_LOCAL}/health -> ${hc.status || 0}`,
      `GET 127.0.0.1:${PORT_LOCAL}/ (Host: ${hostHeader}) -> ${rr.status || 0}`
    ];

    const probes = {
      login: await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/login`),
      reset: await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/reset`),
      session: await httpCheck(`http://127.0.0.1:${PORT_LOCAL}/session/remaining`)
    };

    if (!hc.ok) services.push({ name:'Health', detail:'/health', ok:false });
    if (![200,204,302].includes((probes.login.status||0))) services.push({ name:'Login', detail:'/login', ok:false });
    if (![200,204,302].includes((probes.reset.status||0))) services.push({ name:'Reset', detail:'/reset', ok:false });

    res.set('Cache-Control','no-store');
    res.json({ node, os: osInfo, git, services, net, proxy: { checks: proxyChecks }, routes });
  });

  return router;
};
