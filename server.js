// server.js - Personal MFA Code Generator for Tines Workflows
const express = require('express');
const speakeasy = require('speakeasy');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Your MFA accounts storage (add your accounts here)
const accounts = {
  // Example format:
  // 'google': {
  //   name: 'My Google Account',
  //   secret: 'YOUR_SECRET_KEY_HERE',
  //   digits: 6,
  //   period: 30
  // },
  // 'github': {
  //   name: 'GitHub',
  //   secret: 'ANOTHER_SECRET_KEY',
  //   digits: 6,
  //   period: 30
  // }
};

// Simple encryption for secrets (optional, but recommended)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// 1. Get MFA code for specific account (THIS IS WHAT TINES WILL CALL)
app.get('/api/code/:accountKey', (req, res) => {
  try {
    const { accountKey } = req.params;
    
    const account = accounts[accountKey];
    
    if (!account) {
      return res.status(404).json({ 
        error: 'Account not found',
        availableAccounts: Object.keys(accounts)
      });
    }
    
    // Check if secret is encrypted
    let secret = account.secret;
    if (account.encrypted) {
      secret = decrypt(secret);
    }
    
    // Generate TOTP using RFC 6238 standard (same as Google/Microsoft Authenticator)
    const token = speakeasy.totp({
      secret: secret,
      encoding: 'base32',
      algorithm: 'sha1',  // Standard TOTP uses SHA1 (same as Google/MS Authenticator)
      digits: account.digits || 6,
      step: account.period || 30,
      window: 0  // No time window tolerance for exact matching
    });
    
    // Calculate time remaining
    const epoch = Math.round(new Date().getTime() / 1000.0);
    const period = account.period || 30;
    const timeRemaining = period - (epoch % period);
    
    res.json({
      account: account.name || accountKey,
      code: token,
      timeRemaining: timeRemaining,
      expiresAt: new Date(Date.now() + (timeRemaining * 1000)).toISOString()
    });
  } catch (err) {
    console.error('Error generating code:', err);
    res.status(500).json({ error: 'Failed to generate code' });
  }
});

// 2. Get ALL MFA codes at once
app.get('/api/codes', (req, res) => {
  try {
    const epoch = Math.round(new Date().getTime() / 1000.0);
    
    const codes = Object.entries(accounts).map(([key, account]) => {
      try {
        let secret = account.secret;
        if (account.encrypted) {
          secret = decrypt(secret);
        }
        
        const token = speakeasy.totp({
          secret: secret,
          encoding: 'base32',
          algorithm: 'sha1',  // Standard TOTP uses SHA1
          digits: account.digits || 6,
          step: account.period || 30,
          window: 0
        });
        
        const period = account.period || 30;
        const timeRemaining = period - (epoch % period);
        
        return {
          key: key,
          name: account.name || key,
          code: token,
          timeRemaining: timeRemaining
        };
      } catch (err) {
        return {
          key: key,
          name: account.name || key,
          error: 'Failed to generate code'
        };
      }
    });
    
    res.json({ codes });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 3. Add new account (for easy setup)
app.post('/api/accounts', (req, res) => {
  try {
    const { key, name, secret, digits, period, encrypt: shouldEncrypt } = req.body;
    
    if (!key || !secret) {
      return res.status(400).json({ error: 'key and secret are required' });
    }
    
    if (accounts[key]) {
      return res.status(409).json({ error: 'Account already exists' });
    }
    
    // Validate secret by trying to generate a code (RFC 6238 standard)
    try {
      speakeasy.totp({
        secret: secret,
        encoding: 'base32',
        algorithm: 'sha1'
      });
    } catch (err) {
      return res.status(400).json({ error: 'Invalid secret key' });
    }
    
    accounts[key] = {
      name: name || key,
      secret: shouldEncrypt ? encrypt(secret) : secret,
      encrypted: shouldEncrypt || false,
      digits: digits || 6,
      period: period || 30,
      addedAt: new Date().toISOString()
    };
    
    res.status(201).json({
      message: 'Account added successfully',
      key: key,
      name: accounts[key].name
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 4. List all accounts (without secrets)
app.get('/api/accounts', (req, res) => {
  try {
    const accountList = Object.entries(accounts).map(([key, account]) => ({
      key: key,
      name: account.name || key,
      digits: account.digits || 6,
      period: account.period || 30,
      encrypted: account.encrypted || false,
      addedAt: account.addedAt || 'N/A'
    }));
    
    res.json({
      accounts: accountList,
      total: accountList.length
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 5. Delete account
app.delete('/api/accounts/:key', (req, res) => {
  try {
    const { key } = req.params;
    
    if (!accounts[key]) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    delete accounts[key];
    
    res.json({
      message: 'Account deleted successfully',
      key: key
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    accounts: Object.keys(accounts).length,
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🔐 Personal MFA Code Generator`);
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`\n📋 Quick Start:`);
  console.log(`   GET  /api/code/:accountKey  - Get MFA code for Tines`);
  console.log(`   GET  /api/codes             - Get all codes`);
  console.log(`   POST /api/accounts          - Add new account`);
  console.log(`\n💡 Example Tines usage:`);
  console.log(`   curl http://localhost:${PORT}/api/code/google`);
  console.log(`\n📊 Available accounts: ${Object.keys(accounts).length}`);
  if (Object.keys(accounts).length > 0) {
    console.log(`   ${Object.keys(accounts).join(', ')}`);
  }
  console.log('');
});