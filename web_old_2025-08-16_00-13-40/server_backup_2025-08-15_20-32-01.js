/* server.js (CommonJS) */
require("dotenv").config();
const express = require("express");
const path = require("path");

/* ibelsa-Helper robust einbinden (egal ob default oder named export) */
const ibelsaMod = require("../ibelsa/ibelsa.js");
const ibelsa = ibelsaMod.ibelsa || ibelsaMod.default || ibelsaMod;

const app = express();
const PORT = process.env.PORT || 3011;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* Static Files */
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));

/* Login-Ziel: leitet auf ibelsa.html */
app.post("/login", (_req, res) => res.redirect(303, "/ibelsa.html"));

/* Healthcheck (optional) */
app.get("/health", (_req, res) => res.status(200).send("ok"));

/* API: Hotelinformationen an Frontend durchreichen */
app.get("/api/hotel-info", async (_req, res) => {
  try {
    const data = await ibelsa("/api/hotel/information");
    res.status(200).json(data.data || data);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || "ibelsa error", details: e.details || null });
  }
});

/* Fallback: / zeigt login.html */
app.get("/", (_req, res) => res.sendFile(path.join(publicDir, "login.html")));

app.listen(PORT, () => console.log(`[web] Hotel Dashboard läuft auf http://localhost:${PORT}`));
