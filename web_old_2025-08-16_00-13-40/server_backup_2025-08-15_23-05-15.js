import "dotenv/config";
import express from "express";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";
import { ibelsa } from "./lib/ibelsa.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT || 3011; // Apache Proxy -> 3011

app.disable("x-powered-by");
app.use(express.urlencoded({ extended: true })); // Form-POSTs
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "hotel-dashboard-session",
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: "lax" }
}));

// Static: /public (login.html, ibelsa.html, theme.css)
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Root -> Loginseite
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

// ✅ Login: nimmt Formdaten an und leitet IMMER auf /ibelsa.html
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.redirect("/login.html");
  try { req.session.user = { name: username, at: Date.now() }; } catch {}
  return res.redirect(303, "/ibelsa.html");
});

// Logout
app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/login.html")));

// Server-API -> ibelsa Hotelinformationen (Key bleibt serverseitig)
app.get("/api/hotel-info", async (_req, res) => {
  try {
    const json = await ibelsa("/api/hotel/information");
    return res.json(json.data ?? json);
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message || "Fehler bei ibelsa" });
  }
});

// Healthcheck
app.get("/healthz", (_req, res) => res.json({ ok: true, t: Date.now() }));

// 404-Fallback (verhindert „Cannot POST /…“ Defaultseite)
app.use((req, res) => res.status(404).send(`Pfad nicht gefunden: ${req.method} ${req.path}`));

// Start
app.listen(PORT, () => console.log(`[hotel-dashboard] Server läuft auf Port ${PORT}`));
