const express = require("express");
const router = express.Router();

router.post("/login", (req,res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).send("Benutzername/Passwort fehlt.");
  }
  try { if (req.session) req.session.user = { name: username }; } catch(e){}
  return res.redirect(303, "/ibelsa.html");
});

router.get("/logout", (req,res) => {
  try { req.session?.destroy?.(()=>{}); } catch(e){}
  res.redirect(303, "/login.html");
});

module.exports = router;
