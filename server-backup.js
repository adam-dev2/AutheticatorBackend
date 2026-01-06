// server.js – Personal MFA Code Generator (FIXED)
const express = require('express');
const speakeasy = require('speakeasy');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

/* =====================================================
   🔐 CONFIG
===================================================== */

// MUST be static or secrets break after restart
if (!process.env.ENCRYPTION_KEY) {
  console.warn('⚠️  ENCRYPTION_KEY not set. Secrets will break on restart.');
}

const ENCRYPTION_KEY = crypto
  .createHash('sha256')
  .update(process.env.ENCRYPTION_KEY || 'dev-secret')
  .digest(); // 32 bytes


/* =====================================================
   🔧 HELPERS
===================================================== */

function normalizeBase32(secret) {
  return secret.replace(/\s+/g, '').toUpperCase();
}

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    iv
  );
  const encrypted = Buffer.concat([
    cipher.update(text, 'utf8'),
    cipher.final()
  ]);
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(text) {
  const [ivHex, encryptedHex] = text.split(':');
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    Buffer.from(ivHex, 'hex')
  );
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

/* =====================================================
   🗄️ IN-MEMORY STORE
===================================================== */

const accounts = {};

/* =====================================================
   🔢 OTP GENERATOR
===================================================== */

function generateOTP(account) {
  let secret = account.secret;
  if (account.encrypted) secret = decrypt(secret);

  secret = normalizeBase32(secret);

  if (account.type === 'hotp') {
    const token = speakeasy.hotp({
      secret,
      encoding: 'base32',
      counter: account.counter || 0,
      digits: account.digits
    });

    account.counter = (account.counter || 0) + 1;
    return { code: token, type: 'hotp' };
  }

  const token = speakeasy.totp({
    secret,
    encoding: 'base32',
    step: account.period,
    digits: account.digits,
    algorithm: account.algorithm || 'sha256', 
    window: 1 // ⏱️ clock drift protection
  });

  const epoch = Math.floor(Date.now() / 1000);
  const remaining = account.period - (epoch % account.period);

  return {
    code: token,
    type: 'totp',
    timeRemaining: remaining
  };
}

/* =====================================================
   🚀 ROUTES
===================================================== */

// 1️⃣ Get single code (Tines-friendly)
app.get('/api/code/:key', (req, res) => {
  const account = accounts[req.params.key];
  if (!account) {
    return res.status(404).json({
      error: 'Account not found',
      available: Object.keys(accounts)
    });
  }

  try {
    const result = generateOTP(account);
    res.json({
      account: account.name,
      ...result
    });
  } catch (e) {
    res.status(500).json({ error: 'OTP generation failed' });
  }
});

// 2️⃣ Get all codes
app.get('/api/codes', (req, res) => {
  const codes = Object.entries(accounts).map(([key, acc]) => {
    try {
      return { key, name: acc.name, ...generateOTP(acc) };
    } catch {
      return { key, name: acc.name, error: 'FAILED' };
    }
  });
  res.json({ codes });
});

// 3️⃣ Add account (AUTO detects TOTP/HOTP)
app.post('/api/accounts', (req, res) => {
  const {
    key,
    name,
    secret,
    digits = 6,
    period = 30,
    type = 'totp',
    algorithm = 'sha256',
    encrypt: shouldEncrypt = true
  } = req.body;

  if (!key || !secret) {
    return res.status(400).json({ error: 'key and secret required' });
  }

  if (accounts[key]) {
    return res.status(409).json({ error: 'Account exists' });
  }

  const cleanSecret = normalizeBase32(secret);

  // Validate secret
  speakeasy.totp({ secret: cleanSecret, encoding: 'base32' });

  accounts[key] = {
    name: name || key,
    secret: shouldEncrypt ? encrypt(cleanSecret) : cleanSecret,
    encrypted: shouldEncrypt,
    digits,
    period,
    type,
    algorithm: algorithm.toLowerCase(),
    addedAt: new Date().toISOString()
  };

  res.status(201).json({ message: 'Account added', key });
});

// 4️⃣ Debug endpoint (USE THIS)
app.get('/api/debug/:key', (req, res) => {
  const acc = accounts[req.params.key];
  if (!acc) return res.status(404).json({ error: 'Not found' });

  let secret = acc.encrypted ? decrypt(acc.secret) : acc.secret;

  res.json({
    normalizedSecret: normalizeBase32(secret),
    serverTime: new Date().toISOString(),
    otp: generateOTP(acc)
  });
});

// 5️⃣ List accounts
app.get('/api/accounts', (req, res) => {
  res.json({
    total: Object.keys(accounts).length,
    accounts: Object.entries(accounts).map(([k, v]) => ({
      key: k,
      name: v.name,
      type: v.type,
      digits: v.digits,
      period: v.period
    }))
  });
});

// 6️⃣ Delete
app.delete('/api/accounts/:key', (req, res) => {
  delete accounts[req.params.key];
  res.json({ deleted: req.params.key });
});

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

/* =====================================================
   🟢 START
===================================================== */

app.listen(PORT, () => {
  console.log(`🔐 MFA Generator running → http://localhost:${PORT}`);
});