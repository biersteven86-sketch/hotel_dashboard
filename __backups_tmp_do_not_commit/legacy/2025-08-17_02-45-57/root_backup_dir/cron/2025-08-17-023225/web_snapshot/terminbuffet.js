/**
 * Terminbuffet – Beispiel: hier kommt deine eigentliche Logik rein.
 * Aktuell schreibt es nur einen Eintrag und beendet sich.
 */
const fs = require('fs');
const path = require('path');

(async () => {
  const when = new Date().toISOString();
  // TODO: Hier echte Arbeit machen (z.B. Daten abrufen, Dateien erzeugen, …)
  console.log(`[Terminbuffet] Run at ${when}`);
  // Beispiel: Dummy-Datei mit Zeitstempel aktualisieren
  fs.writeFileSync(path.join(__dirname, 'terminbuffet.last'), when + '\n', 'utf8');
  process.exit(0);
})().catch(err => {
  console.error('[Terminbuffet] ERROR:', err && err.stack || err);
  process.exit(1);
});
