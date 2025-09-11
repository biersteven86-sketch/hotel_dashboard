// session-timer.js
// Zeigt oben rechts einen Live-Countdown der verbleibenden Session-Zeit.
// Nutzt /session/remaining (JSON: { ok:true, remaining, idleMs }).
// Bei 0 → Redirect auf /login?timeout=1

(function () {
  const WIDGET_ID = 'hd-session-timer';
  if (document.getElementById(WIDGET_ID)) return;

  // UI
  const box = document.createElement('div');
  box.id = WIDGET_ID;
  box.setAttribute('aria-live', 'polite');
  const style = box.style;
  style.position = 'fixed';
  style.top = '12px';
  style.right = '12px';
  style.zIndex = '2147483647';
  style.padding = '8px 12px';
  style.borderRadius = '12px';
  style.fontFamily = 'system-ui, -apple-system, Segoe UI, Roboto, Arial';
  style.fontSize = '14px';
  style.color = '#fff';
  style.backdropFilter = 'blur(8px)';
  style.webkitBackdropFilter = 'blur(8px)';
  style.background = 'rgba(0,0,0,.55)';
  style.boxShadow = '0 6px 18px rgba(0,0,0,.25)';
  style.userSelect = 'none';
  style.pointerEvents = 'none';
  box.textContent = 'Session: –:––';
  document.addEventListener('DOMContentLoaded', () => {
    document.body.appendChild(box);
  });

  // State
  let remaining = 0;          // ms laut Server
  let idleMs = 300000;        // Standard 5min – wird vom Server überschrieben
  let lastServerTick = Date.now();

  // Utils
  function fmt(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${m}:${String(r).padStart(2, '0')}`;
  }

  function paint(ms) {
    box.textContent = `Session: ${fmt(ms)}`;
    // Warnfarbe bei < 60s
    box.style.background = ms < 60000 ? 'rgba(183,28,28,.70)' : 'rgba(0,0,0,.55)';
  }

  // Poll vom Server (1×/s)
  async function poll() {
    try {
      const res = await fetch('/session/remaining', { cache: 'no-store', credentials: 'same-origin' });
      if (!res.ok) throw new Error('bad status');
      const j = await res.json();
      idleMs = Number(j.idleMs) || idleMs;
      remaining = Number(j.remaining) || 0;
      lastServerTick = Date.now();

      if (remaining <= 0) {
        paint(0);
        location.href = '/login?timeout=1';
        return;
      }
      paint(remaining);
    } catch {
      // Bei Fehler einfach später erneut versuchen (kein Spam)
    } finally {
      setTimeout(poll, 1000);
    }
  }

  // Lokales „Ticken“ zwischen den Server-Polls (flüssiger Countdown)
  setInterval(() => {
    if (remaining > 0) {
      const elapsed = Date.now() - lastServerTick;
      const approx = Math.max(0, remaining - elapsed);
      paint(approx);
      if (approx <= 0) location.href = '/login?timeout=1';
    }
  }, 250);

  // Start
  poll();
})();
