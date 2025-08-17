/* server.js (CommonJS, Port 3011) */
require("dotenv").config();
const express = require("express");
const path = require("path");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 3011;

app.disable("x-powered-by");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "hotel-dashboard-session",
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: "lax" }
}));

// Statische Dateien (login.html, ibelsa.html)
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Root -> Loginseite
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

// ROBUSTE Login-Route: fängt POST (und notfalls alles andere) ab und leitet IMMER weiter
app.all("/login", (req, res) => {
  if (req.method === "POST") {
    const u = (req.body && req.body.username) || "";
    const p = (req.body && req.body.password) || "";
    if (!u || !p) return res.redirect("/login.html");
    req.session.user = { name: u, at: Date.now() };
    return res.redirect(303, "/ibelsa.html");
  }
  // GET/sonst: zurück auf Login
  return res.redirect("/login.html");
});

// API-Stubs nur zur Verfügbarkeit (später echten ibelsa-Call reaktivieren)
app.get("/api/hotel-info", (_req, res) => res.json({ ok: true, source: "stub", t: Date.now() }));

// Health
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// 404-Fallback
app.use((req, res) => res.status(404).send());

app.listen(PORT, () => console.log());
