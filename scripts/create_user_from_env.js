#!/usr/bin/env node
/**
 * Erstellt Benutzer aus den .env Variablen
 * und schreibt sie in data/users.json
 */

const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');

// Stelle sicher, dass der data-Ordner existiert
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

// Lade .env Variablen
const users = [];
function pushIf(u, p, role) {
  if (!u || !p) return;
  users.push({ username: String(u), password: String(p), role });
}
pushIf(process.env.DASH_USER,   process.env.DASH_PASS,   'dashboard');
pushIf(process.env.ADMIN_USER,  process.env.ADMIN_PASS,  'admin');
pushIf(process.env.IBELSA_USER, process.env.IBELSA_PASS, 'ibelsa');

if (!users.length) {
  console.error('Keine Benutzer in .env gefunden.');
  process.exit(1);
}

console.log('Lege Benutzer an:', users.map(u => u.username).join(', '));
fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
console.log('Benutzer erfolgreich gespeichert in:', USERS_FILE);
