#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Konfiguration
# -----------------------------
PROJECT_DIR="/home/steven/hotel_dashboard"
BACKUP_DIR="/home/steven/backups/hotel_dashboard"
RETENTION_DAYS=30                      # älter als X Tage löschen
TS="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="$BACKUP_DIR/hotel_dashboard-$TS.tar.gz"

mkdir -p "$BACKUP_DIR"

# -----------------------------
# Backup erstellen
#  - excludes: node_modules/.git/logs/tmp/caches/.env etc.
# -----------------------------
tar -czf "$ARCHIVE" -C "/home/steven" \
  --exclude='hotel_dashboard/node_modules' \
  --exclude='hotel_dashboard/.git' \
  --exclude='hotel_dashboard/.cache' \
  --exclude='hotel_dashboard/*.log' \
  --exclude='hotel_dashboard/logs' \
  --exclude='hotel_dashboard/tmp' \
  --exclude='hotel_dashboard/.env' \
  --exclude='hotel_dashboard/scripts/*.tar.gz' \
  --exclude='hotel_dashboard/public/*backup*' \
  hotel_dashboard

# Prüfsumme sichern (Integritätscheck)
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

# -----------------------------
# Rotation/Retention
# -----------------------------
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -regextype posix-extended \
  -regex '.*\.(tar\.gz|sha256)$' -delete

echo "[OK] Backup erstellt: $ARCHIVE"
