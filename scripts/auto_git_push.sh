#!/usr/bin/env bash
set -euo pipefail
cd /home/steven/hotel_dashboard

BRANCH=main
git config user.name  "Steven Bier (Auto)"
git config user.email "biersteven86-sketch@github.com"

echo "[auto-push] watching for changes…"
# Beobachte nur relevante Pfade (keine .env!)
while inotifywait -e modify,create,delete,move -r \
  server.js lib public terminbuffet.js users.json package.json package-lock.json 2>/dev/null; do

  # Nur committen, wenn wirklich staged Changes anstehen
  git add -A
  if ! git diff --cached --quiet; then
    MSG="auto: $(date +'%F %T') on $(hostname)"
    git commit -m "$MSG" || true
    git pull --rebase origin "$BRANCH" || true
    git push origin "$BRANCH" || true
    echo "[auto-push] committed & pushed."
  else
    echo "[auto-push] nothing to commit."
  fi
done
