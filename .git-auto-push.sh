#!/usr/bin/env bash
set -euo pipefail

REPO="/home/steven/hotel_dashboard"
LOCK="/tmp/git-auto-push.lock"
EXCLUDE='(^|/)\.git/|server\.out\.log$|\.swp$|\.tmp$|^data/|^node_modules/|\.env$'

cd "$REPO"

# Sicherstellen, dass origin existiert
git remote get-url origin >/dev/null 2>&1

# Debounce-Mechanismus: sammelt Events kurz und pusht dann
sync_now() {
  # Nur ein Prozess gleichzeitig
  exec 9>"$LOCK"
  flock -n 9 || return 0

  # Kurze Sammelzeit
  sleep 3

  # Alles hinzufügen, was nicht von .gitignore ausgeschlossen ist
  git add -A

  # Nichts zu committen?
  if git diff --cached --quiet; then
    echo "[auto] nichts zu committen"
    return 0
  fi

  # Commit-Message mit Zeitpunkt & Host
  TS="$(date +'%F %T')"
  HOST="$(hostname -s || echo host)"
  git commit -m "auto: ${TS} (${HOST})"

  # Sauber rebasen & pushen
  git pull --rebase --autostash origin main || true
  git push origin HEAD:main
  echo "[auto] gepusht @ ${TS}"
}

# Initial einmalig Status ausgeben
echo "[auto] watcher startet in $REPO"

# Dauerhaft beobachten (rekursiv)
inotifywait -m -r -e modify,move,create,delete --exclude "$EXCLUDE" "$REPO" | \
while read -r _; do
  sync_now
done
