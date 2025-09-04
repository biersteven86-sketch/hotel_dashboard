#!/usr/bin/env bash
# Sichert beliebige Projektdateien außerhalb des Repos in einen datierten Snapshot.
# Nutzung: safe_backup.sh [-n] <datei> [weitere dateien...]
#   -n  Dry-Run (zeigt nur, was kopiert würde)

set -euo pipefail

PROJECT="/home/steven/hotel_dashboard"
DST_ROOT="/home/steven/backups/hotel_dashboard/project_snapshots"
STAMP="$(date +%F-%H%M%S)"
DST_DIR="${DST_ROOT}/${STAMP}"

DRY=0
while getopts ":n" opt; do
  case "$opt" in
    n) DRY=1 ;;
    *) echo "Usage: $(basename "$0") [-n] <file> [file...]" >&2; exit 2;;
  esac
done
shift $((OPTIND-1))

if [ $# -lt 1 ]; then
  echo "Usage: $(basename "$0") [-n] <file> [file...]" >&2
  exit 2
fi

mkdir -p "$DST_DIR"
MANIFEST="$DST_DIR/manifest.txt"
SUMS_DIR="$DST_ROOT"
mkdir -p "$SUMS_DIR"

echo "# Snapshot ${STAMP}"        | tee "$MANIFEST" >/dev/null
echo "# Root:    ${DST_DIR}"     | tee -a "$MANIFEST" >/dev/null
echo "# DRYRUN:  ${DRY}"         | tee -a "$MANIFEST" >/dev/null
echo "# Files:"                   | tee -a "$MANIFEST" >/dev/null

copied_any=0
for SRC in "$@"; do
  # Absolutieren & verifizieren
  if [[ "$SRC" != /* ]]; then SRC="${PROJECT}/${SRC}"; fi
  if [ ! -e "$SRC" ]; then
    echo "MISS: ${SRC}" | tee -a "$MANIFEST" >/dev/null
    continue
  fi

  # Pfad relativ zum Projekt abbilden
  REL="${SRC#${PROJECT}/}"
  REL="${REL#/}" # leading slash weg
  TARGET="${DST_DIR}/${REL}"
  mkdir -p "$(dirname "$TARGET")"

  if [ "$DRY" -eq 1 ]; then
    echo "[DRY] $SRC -> $TARGET" | tee -a "$MANIFEST" >/dev/null
  else
    cp -a "$SRC" "$TARGET"
    sha256sum "$TARGET" >> "${DST_DIR}/sha256sums.txt"
    echo "OK  : $SRC -> $TARGET" | tee -a "$MANIFEST" >/dev/null
    copied_any=1
  fi
done

if [ "$DRY" -eq 0 ] && [ "$copied_any" -eq 1 ]; then
  ( cd "$DST_DIR" && tar -czf "../snapshot-${STAMP}.tar.gz" . )
  ( cd "$DST_ROOT" && sha256sum "snapshot-${STAMP}.tar.gz" >> sha256sums.txt )
fi

echo
echo "Snapshot: $DST_DIR"
if [ "$DRY" -eq 0 ] && [ "$copied_any" -eq 1 ]; then
  echo "Archiv  : ${DST_ROOT}/snapshot-${STAMP}.tar.gz"
fi
