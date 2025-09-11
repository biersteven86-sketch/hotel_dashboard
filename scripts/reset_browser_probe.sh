#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-127.0.0.1:3000}"      # <- ggf. auf 100.72.171.99:3000 anpassen (genau wie du IM BROWSER testest)
ERR="$HOME/.pm2/logs/hotel-dashboard-error.log"
OUT="$HOME/.pm2/logs/hotel-dashboard-out.log"
TOK="data/auth/reset.db.json"

echo "== A) reset.html: SERVED vs LOCAL (sha256) =="
srvSum="$(curl -s http://$HOST/reset | sha256sum | awk '{print $1}')" || srvSum="ERR"
locSum="$(sha256sum public/reset.html 2>/dev/null | awk '{print $1}')" || locSum="NOFILE"
echo "  SERVED sha256: $srvSum"
echo "  LOCAL  sha256: $locSum"
echo

echo "== B) reset.html: Form + JS-Auszug (fetch/submit) =="
echo "-- Form/Inputs --"
grep -n '<form' public/reset.html | head -n 5 || true
grep -n 'name="email"' public/reset.html | head -n 5 || true
echo
echo "-- JS: fetch/submit Handler --"
grep -n 'fetch(' -n public/reset.html || true
grep -n 'form-forgot' public/reset.html || true
# JS-Blöcke zeigen (alle <script> ... </script>)
awk 'BEGIN{print "----- JS BEGIN -----"} /<script/{in=1} in{print} /<\/script>/{in=0} END{print "----- JS END -----"}' public/reset.html | sed -n '1,220p'
echo

echo "== C) Logs zurücksetzen =="
: > "$ERR" || true
: > "$OUT" || true
echo "  Logs geleert."

echo
echo "== D) Jetzt im BROWSER auf http://$HOST/reset gehen und \"Link zusenden\" klicken."
read -p "Wenn du GEKLICKT hast, ENTER drücken, damit die Auswertung startet ... " _

echo
echo "== E) Frische Logs (ohne Stream) =="
echo "-- ERROR --"
tail -n 80 "$ERR" | sed 's/^/[ERR] /' || true
echo "-- OUT --"
tail -n 120 "$OUT" | sed 's/^/[OUT] /' || true

echo
echo "== F) Token-Datei (mtime + Inhalt) =="
stat -c '%y %s bytes  -> %n' "$TOK" 2>/dev/null || echo "Token-Datei fehlt: $TOK"
echo "--- Inhalt ---"
jq '.' "$TOK" 2>/dev/null || cat "$TOK" 2>/dev/null || true

echo
echo "== G) Optional: Genau wie der Browser posten (urlencoded) =="
curl -i -L -c /tmp/hd.cookies -b /tmp/hd.cookies \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'email=info@myhome-rottweil.de' \
  "http://$HOST/reset"
