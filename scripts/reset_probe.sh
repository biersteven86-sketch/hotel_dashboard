#!/usr/bin/env bash
set -euo pipefail

# ==== ggf. anpassen ====
HOST="${HOST:-127.0.0.1:3000}"   # z.B. 127.0.0.1:3000 oder 100.72.171.99:3000
TO="${TO:-info@myhome-rottweil.de}"

ERR="$HOME/.pm2/logs/hotel-dashboard-error.log"
OUT="$HOME/.pm2/logs/hotel-dashboard-out.log"

echo "== A) Welche reset.html wird SERVED vs. lokale Datei? =="
srvSum="$(curl -s http://$HOST/reset | sha256sum | awk '{print $1}')" || srvSum="ERR"
locSum="$(sha256sum public/reset.html 2>/dev/null | awk '{print $1}')" || locSum="NOFILE"
echo "  SERVED sha256: $srvSum"
echo "  LOCAL  sha256: $locSum"
echo

echo "== B) reset.html: form/action/method + name=email =="
grep -n '<form'          public/reset.html | head -n 3 || true
grep -n 'action='        public/reset.html | head -n 3 || true
grep -n 'method='        public/reset.html | head -n 3 || true
grep -n 'name="email"'   public/reset.html | head -n 3 || true
echo

echo "== C) Route/Whitelist in server.js =="
grep -n 'OPEN_PATHS' server.js || true
grep -n "app.post('/reset'" server.js || true
echo

echo "== D1) Browser-Weg simulieren (POST urlencoded) =="
curl -i -L -c /tmp/hd.cookies -b /tmp/hd.cookies \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "email=${TO}" "http://$HOST/reset" | sed -n '1,15p'
echo

echo "== D2) Alternativ: POST als JSON (falls Frontend fetch(JSON) nutzt) =="
curl -i -L -c /tmp/hd.cookies -b /tmp/hd.cookies \
  -H 'Content-Type: application/json' \
  --data "{\"email\":\"${TO}\"}" "http://$HOST/reset" | sed -n '1,15p'
echo

echo "== E) Letzte Logs (ohne Stream) =="
tail -n 80 "$OUT" 2>/dev/null | sed 's/^/[OUT] /' | tail -n 30
tail -n 40 "$ERR" 2>/dev/null | sed 's/^/[ERR] /'
echo

echo "== F) Token-Datei =="
ls -l data/auth/reset.db.json || true
jq '.' data/auth/reset.db.json 2>/dev/null || cat data/auth/reset.db.json
