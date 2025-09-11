// routes.reset.js — Reset-Routen
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const express = require('express');

const router = express.Router();
router.use(express.json());
router.use(express.urlencoded({ extended: true }));

const DATA_DIR   = __dirname;
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TOKENS_FILE= path.join(DATA_DIR, 'reset_tokens.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.log');

async function ensureFileJSON(filePath, initialValue){
  try{ await fsp.access(filePath); }
  catch{ await fsp.writeFile(filePath, JSON.stringify(initialValue,null,2)); }
}
async function readJSON(filePath,fallback){
  try{ const raw = await fsp.readFile(filePath,'utf8'); return JSON.parse(raw||'null') ?? fallback; }
  catch{ return fallback; }
}
async function writeJSON(filePath,obj){ await fsp.writeFile(filePath, JSON.stringify(obj,null,2)); }
function getClientIP(req){
  const xf=req.headers['x-forwarded-for'];
  return typeof xf==='string'&&xf.length?xf.split(',')[0].trim():(req.socket?.remoteAddress||'');
}
async function auditLog(event,details){
  await fsp.appendFile(AUDIT_FILE, JSON.stringify({ts:new Date().toISOString(),event,...details})+'\n');
}
function validatePasswordPolicy(pw){
  if(!pw || pw.length<10) return false;
  const lower=/[a-z]/.test(pw), upper=/[A-Z]/.test(pw), digit=/\d/.test(pw), special=/[^A-Za-z0-9]/.test(pw);
  return lower && upper && (digit || special);
}
async function initFiles(){
  await ensureFileJSON(USERS_FILE,[]);
  await ensureFileJSON(TOKENS_FILE,[]);
  try{ await fsp.access(AUDIT_FILE); } catch{ await fsp.writeFile(AUDIT_FILE,''); }
}

// ---------- GET /reset/validate ----------
router.get('/reset/validate', async (req,res) => {
  await initFiles();
  try{
    const email = String(req.query.email||'').trim().toLowerCase();
    const token = String(req.query.token||'').trim();
    if(!email || !token) return res.status(400).json({ok:false,error:'missing_parameters'});

    const tokens = await readJSON(TOKENS_FILE,[]);
    const hit = tokens.find(t => t.email===email && t.token===token);
    if(!hit) return res.status(400).json({ok:false,error:'invalid_token'});
    if(hit.used) return res.status(400).json({ok:false,error:'token_used'});
    if(Date.now()>hit.expiresAt) return res.status(400).json({ok:false,error:'token_expired'});

    return res.json({ok:true});
  }catch(e){
    console.error(e);
    return res.status(500).json({ok:false,error:'server_error'});
  }
});

// ---------- POST /reset/confirm ----------
router.post('/reset/confirm', async (req,res) => {
  await initFiles();
  try{
    const emailRaw = String(req.body.email||'').trim();
    const email = emailRaw.toLowerCase();
    const token = String(req.body.token||'').trim();
    const firstname = String(req.body.firstname||'').trim();
    const lastname  = String(req.body.lastname||'').trim();
    const password  = String(req.body.password||'');

    if(!email || !token || !firstname || !lastname || !password){
      return res.status(400).json({ok:false,error:'missing_parameters'});
    }

    const tokens = await readJSON(TOKENS_FILE,[]);
    const idx = tokens.findIndex(t => t.email===email && t.token===token);
    if(idx===-1) return res.status(400).json({ok:false,error:'invalid_token'});

    const t = tokens[idx];
    if(t.used) return res.status(400).json({ok:false,error:'token_used'});
    if(Date.now()>t.expiresAt) return res.status(400).json({ok:false,error:'token_expired'});

    if(!validatePasswordPolicy(password)){
      return res.status(422).json({ok:false,error:'weak_password'});
    }

    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password,salt);

    const users = await readJSON(USERS_FILE,[]);
    const uIdx = users.findIndex(u => (u.email||'').toLowerCase()===email);
    const record = { email, passwordHash:hash, passwordUpdatedAt:new Date().toISOString() };
    if(uIdx===-1) users.push(record); else users[uIdx] = { ...users[uIdx], ...record };
    await writeJSON(USERS_FILE, users);

    tokens[idx].used = true;
    await writeJSON(TOKENS_FILE, tokens);

    await auditLog('reset.confirm', { email, firstname, lastname, ip:getClientIP(req) });

    return res.json({ok:true,redirect:'/login.html?reset=1'});
  }catch(e){
    console.error(e);
    return res.status(500).json({ok:false,error:'server_error'});
  }
});

module.exports = router;
