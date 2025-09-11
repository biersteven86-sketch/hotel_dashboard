#!/usr/bin/env bash
set -euo pipefail

# --- KONFIG ---
REPO_DIR="/home/steven/hotel_dashboard"
KEY_TITLE="RaspberryPi Hotel-Dashboard"   # frei wählbar
ACCESS_FILE="${REPO_DIR}/git hub zugang.txt"  # 1. Zeile: username, 2. Zeile: token
GITHUB_API="https://api.github.com"

# --- 0) Repo-Ordner und .ssh vorbereiten ---
mkdir -p "${REPO_DIR}" ~/.ssh
cd "${REPO_DIR}"

# --- 1) SSH-Key sicherstellen ---
if [ ! -f ~/.ssh/id_ed25519 ]; then
  echo "Kein SSH-Key gefunden. Erzeuge neuen ed25519 Key (ohne Passphrase)…"
  ssh-keygen -t ed25519 -C "raspi@hotel-dashboard" -f ~/.ssh/id_ed25519 -N ""
fi
PUBKEY=$(cat ~/.ssh/id_ed25519.pub | tr -d '\n')
if [ -z "${PUBKEY}" ]; then
  echo "Öffentlicher Key ist leer – Abbruch." >&2
  exit 1
fi

# --- 2) GitHub-Credentials laden ---
GITHUB_USER="${GITHUB_USER:-}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Falls nicht via ENV gesetzt: aus Datei lesen (1. Zeile USER, 2. Zeile TOKEN)
if [ -z "${GITHUB_USER}" ] || [ -z "${GITHUB_TOKEN}" ]; then
  if [ -f "${ACCESS_FILE}" ]; then
    GITHUB_USER=$(sed -n '1p' "${ACCESS_FILE}" | tr -d '\r\n')
    GITHUB_TOKEN=$(sed -n '2p' "${ACCESS_FILE}" | tr -d '\r\n')
  fi
fi

if [ -z "${GITHUB_USER}" ] || [ -z "${GITHUB_TOKEN}" ]; then
  echo "GitHub-Zugangsdaten fehlen. Setze ENV (GITHUB_USER/GITHUB_TOKEN) oder lege '${ACCESS_FILE}' (Zeile1: User, Zeile2: Token) an." >&2
  exit 1
fi

# --- 3) Bestehende SSH-Keys abfragen und alte(n) mit gleichem Title löschen ---
echo "Hole bestehende SSH-Keys von GitHub…"
KEYS_JSON=$(curl -fsS -H "Authorization: token ${GITHUB_TOKEN}" "${GITHUB_API}/user/keys")

# IDs mit gleichem Titel suchen
DEL_IDS=$(echo "${KEYS_JSON}" | grep -n '"id"' -n | cut -d: -f2 | tr -d ' ' || true)
# Sauberer: jq wäre besser; ohne jq:
# wir extrahieren Blöcke mit "id" + "title"
echo "${KEYS_JSON}" | awk -v title="${KEY_TITLE}" '
  /^{/ {blk="";} 
  {blk=blk $0 "\n"} 
  /}/ {
    if (blk ~ /"title"[[:space:]]*:[[:space:]]*"'\"'"'"title"'"'\"'"/) {
      if (blk ~ /"id"[[:space:]]*:[[:space:]]*([0-9]+)/) {
        match(blk, /"id"[[:space:]]*:[[:space:]]*([0-9]+)/, m);
        print m[1];
      }
    }
  }' | while read -r ID; do
    echo "Lösche alten Key mit ID ${ID} (Title='${KEY_TITLE}')…"
    curl -fsS -X DELETE -H "Authorization: token ${GITHUB_TOKEN}" "${GITHUB_API}/user/keys/${ID}" >/dev/null || true
  done

# --- 4) Neuen Key anlegen ---
echo "Lege neuen SSH-Key bei GitHub an: '${KEY_TITLE}'…"
CREATE_OUT=$(curl -fsS -X POST \
  -H "Authorization: token ${GITHUB_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(printf '{"title":"%s","key":"%s"}' "${KEY_TITLE}" "${PUBKEY}")" \
  "${GITHUB_API}/user/keys")

# Erfolg prüfen
echo "${CREATE_OUT}" | grep -q '"id":' || { echo "Fehler beim Anlegen des SSH-Keys. Antwort:"; echo "${CREATE_OUT}"; exit 1; }
echo "✅ SSH-Key bei GitHub aktualisiert."

# --- 5) Remote-URL auf SSH stellen ---
echo "Setze git remote auf SSH…"
git remote set-url origin "git@github.com:${GITHUB_USER}/hotel_dashboard.git"

# --- 6) Verbindung testen ---
echo "Teste SSH zu GitHub…"
ssh -T git@github.com || true

# --- 7) Test-Push (ohne Änderungen überspringt git automatisch) ---
echo "Versuche Push (falls Commits anstehen)…"
git push -u origin main || true

echo "Fertig. Wenn oben keine Fehler standen, sind SSH-Key & Push eingerichtet."
