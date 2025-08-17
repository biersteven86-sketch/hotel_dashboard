#!/bin/bash
set -e

echo "[SETUP] Status-Dashboard aktualisieren und Passwortschutz einrichten..."

# 1. Status.html neu erzeugen
cat > /home/steven/hotel_dashboard/web/public/status.html <<HTML
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <title>Status-Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; background:#f2f2f2; margin:0; padding:0; }
    .container { max-width:800px; margin:50px auto; background:#fff; padding:20px; border-radius:6px; }
    h1 { color:#333; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Server Status</h1>
    <p>Alles läuft korrekt ✅</p>
  </div>
</body>
</html>
HTML

# 2. .htpasswd für Admin/Passwort "Rottweil.12"
htpasswd -bc /home/steven/hotel_dashboard/.htpasswd admin "Rottweil.12"

# 3. Apache Config für Passwortschutz Status-Seite
cat > /etc/apache2/conf-available/status-protect.conf <<APACHE
<Files "status.html">
  AuthType Basic
  AuthName "Geschützt"
  AuthUserFile /home/steven/hotel_dashboard/.htpasswd
  Require valid-user
</Files>
APACHE

a2enconf status-protect
systemctl reload apache2

echo "[FERTIG] Status-Dashboard aktualisiert & Passwortschutz aktiv."
