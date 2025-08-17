import "dotenv/config";
import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import { ibelsa } from "./lib/ibelsa.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3011;

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET || "hotel-dashboard-session",
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: "lax" }
}));

// Body Parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Static Files
app.use(express.static(path.join(__dirname, "public")));

// GET / -> Loginseite
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// POST /login -> Weiterleitung auf ibelsa.html
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.redirect("/login.html");
  }
  req.session.user = { name: username, loginTime: Date.now() };
  return res.redirect("/ibelsa.html");
});

// GET /logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login.html"));
});

// API: Hotelinformationen
app.get("/api/hotel-info", async (_req, res) => {
  try {
    const data = await ibelsa("/api/hotel/information");
    res.json(data.data || data);
  } catch (err) {
    res.status(err.status || 500).send(err.message || "Fehler bei ibelsa");
  }
});

// 404-Fallback
app.use((req, res) => {
  res.status(404).send(\`Pfad nicht gefunden: \${req.method} \${req.path}\`);
});

// Server starten
app.listen(PORT, () => {
  console.log(\`[hotel-dashboard] Server läuft auf Port \${PORT}\`);
});
