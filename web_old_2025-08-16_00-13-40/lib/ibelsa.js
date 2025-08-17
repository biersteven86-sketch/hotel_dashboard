// lib/ibelsa.js – nur Server-Side verwenden!
import fetch from 'node-fetch';

const API_BASE = process.env.IBELSA_API_BASE || 'https://rooms.ibelsa.com';
const API_KEY = process.env.IBELSA_API_KEY;
const SYSTEM_KEY = process.env.IBELSA_SYSTEM_KEY || '';

if (!API_KEY) {
  console.warn('[ibelsa] IBELSA_API_KEY fehlt – .env prüfen.');
}

export async function ibelsa(path, { method = 'GET', headers = {}, body } = {}) {
  const url = path.startsWith('http') ? path : `${API_BASE}${path}`;
  const finalHeaders = {
    'x-ibelsa-key': API_KEY,
    ...(SYSTEM_KEY ? { 'x-ibelsa-system-key': SYSTEM_KEY } : {}),
    'Content-Type': 'application/json',
    ...headers
  };
  const res = await fetch(url, {
    method,
    headers: finalHeaders,
    redirect: 'follow',
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); }
  catch { throw new Error(`[ibelsa] Ungültige Antwort (${res.status}): ${text.slice(0,200)}`); }
  if (!res.ok || json.success === false) {
    const err = new Error(`[ibelsa] API-Fehler: ${json?.message || json?.error || 'HTTP '+res.status}`);
    err.status = res.status; err.details = json?.data || json; throw err;
  }
  return json;
}
