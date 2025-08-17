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

app.use(session({
  secret: process.env.SESSION_SECRET || "hotel-dashboard-session",
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: "lax" }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.redirect("/login.html");
  }
  req.session.user = { name: username, loginTime: Date.now() };
  return res.redirect("/ibelsa.html");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login.html"));
});

app.get("/api/hotel-info", async (_req, res) => {
  try {
    const data = await ibelsa("/api/hotel/information");
    return res.json(data.data || data);
  } catch (err) {
    return res.status(err.status || 500).send(err.message || "Fehler bei ibelsa");
  }
});

app.use((req, res) => {
  res.status(404).send(\`Pfad nicht gefunden: \${req.method} \${req.path}\`);
});

app.listen(PORT, () => {
  console.log(\`[hotel-dashboard] Server läuft auf Port \${PORT}\`);
});
