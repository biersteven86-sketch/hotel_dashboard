#!/bin/bash
# restart_hotel.sh – leert PM2 Cache und startet Hotel-Dashboard neu

echo "[INFO] Starte Hotel-Dashboard Autorestart..."
date
pm2 flush
pm2 restart hotel-web --update-env
echo "[INFO] Hotel-Dashboard wurde neu gestartet."
