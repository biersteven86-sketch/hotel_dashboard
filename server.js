cat > /home/steven/hotel_dashboard/server.js <<'EOF'
const express   = require('express');
const path      = require('path');
const session   = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ quiet: true });

const app  = express();
// Lokal 3000, sonst $PORT (z.B. Render). Siehe Projekt-Referenz.
const PORT = process.env.PORT || 3000; // :contentReference[oaicite:2]{index=2}

// --- Basics ---
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Session ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-please',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, sameSite: 'lax', secure: false,
    maxAge: 60 * 60 * 1000
  }
}));

// --- Rate Limit nur für Login ---
const lo
