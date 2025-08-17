import express from "express";
import path from "path";
import bodyParser from "body-parser";
import session from "express-session";
import { fileURLToPath } from "url";
import { ibelsa } from "./lib/ibelsa.js";
import dotenv from "dotenv";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: "hotel-dashboard-secret", resave: false, saveUninitialized: true }));
app.use(express.static(path.join(__dirname, "public")));

// Login POST
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username && password) {
    req.session.user = username;
    return res.redirect("/ibelsa.html");
  }
  res.status(401).send("Login fehlgeschlagen");
});

// API: Hotelinfo von ibelsa
app.get("/api/hotel-info", async (req, res) => {
  try {
    const data = await ibelsa("/api/hotel/information");
    res.json(data.data);
  } catch (err) {
    res.status(500).json({ error: err.message, details: err.details || null });
  }
});

// Start
const PORT = 3011;
app.listen(PORT, () => {
  console.log(`Hotel-Dashboard läuft auf Port ${PORT}`);
});
