#!/usr/bin/env bash
set -euo pipefail

# ===== ggf. anpassen =====
HOST="127.0.0.1:3000"          # z.B. 127.0.0.1:3000 oder 100.72.171.99:3000
TO="info@myhome-rottweil.de"
ERR="$HOME/.pm2/logs/hotel-dashboard-error.log"
OUT="$HOME/.pm2/logs/hotel-dashboard-out.log"

echo "== A) Letzte Logs (ohne Stream) =="
tail -n 60 "$ERR" 2>/dev/null | sed 's/^/[ERR] /' || true
tail -n 60 "$OUT" 2>/dev/null | sed 's/^/[OUT] /' || true

echo
echo "== B) Route/Whitelist prüfen =="
grep -n "OPEN_PATHS" server.js || true
grep -n "app.post('/reset'" server.js || true

echo
echo "== C) reset.html: action + name=email =="
grep -n "form"          public/reset.html | head -n 3 || true
grep -n "action="       public/reset.html | head -n 3 || true
grep -n 'name="email"'  public/reset.html | head -n 3 || true

echo
echo "== D) Browser-Weg nachstellen (Cookies + Redirects) =="
curl -i -L -c /tmp/hd.cookies -b /tmp/hd.cookies \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "email=${TO}" \
  "http://${HOST}/reset"

echo
echo "== E) Frische Logs nach dem POST (ohne Stream) =="
tail -n 80 "$ERR" 2>/dev/null | sed 's/^/[ERR] /' || true
tail -n 80 "$OUT" 2>/dev/null | sed 's/^/[OUT] /' || true

echo
echo "== F) Token-Datei =="
ls -l data/auth/reset.db.json || true
( command -v jq >/dev/null 2>&1 && jq '.' data/auth/reset.db.json ) \
  || cat data/auth/reset.db.json 2>/dev/null || echo "keine Datei"
