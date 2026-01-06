// server.js - Personal MFA Code Generator with MongoDB
const express = require('express');
const mongoose = require('mongoose');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/mfa-authenticator';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Import Account Model
const Account = require('./models/Account');

// Encryption setup
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
app.get('/api/code/:accountKey', async (req, res) => {
  try {
    const { accountKey } = req.params;
    
    const account = await Account.findByKey(accountKey);
    
    if (!account) {
      const allAccounts = await Account.find({}, 'key').lean();
      return res.status(404).json({ 
        error: 'Account not found',
        availableAccounts: allAccounts.map(a => a.key)
      });
    }
    
    // Check if secret is encrypted
    let secret = account.secret;
    if (account.encrypted) {
      secret = decrypt(secret);
    }
    
    // Generate TOTP using RFC 6238 standard
    const token = speakeasy.totp({
      secret: secret,
      encoding: 'base32',
      algorithm: account.algorithm,
      digits: account.digits,
      step: account.period,
      window: 0
    });
    
    // Calculate time remaining
    const epoch = Math.round(new Date().getTime() / 1000.0);
    const timeRemaining = account.period - (epoch % account.period);
    
    res.json({
      account: account.name || accountKey,
      code: token,
      algorithm: account.algorithm,
      timeRemaining: timeRemaining,
      expiresAt: new Date(Date.now() + (timeRemaining * 1000)).toISOString()
    });
  } catch (err) {
    console.error('Error generating code:', err);
    res.status(500).json({ error: 'Failed to generate code', details: err.message });
  }
});

// 2. Get ALL MFA codes at once
app.get('/api/codes', async (req, res) => {
  try {
    const accounts = await Account.find({});
    const epoch = Math.round(new Date().getTime() / 1000.0);
    
    const codes = accounts.map(account => {
      try {
        let secret = account.secret;
        if (account.encrypted) {
          secret = decrypt(secret);
        }
        
        const token = speakeasy.totp({
          secret: secret,
          encoding: 'base32',
          algorithm: account.algorithm,
          digits: account.digits,
          step: account.period,
          window: 0
        });
        
        const timeRemaining = account.period - (epoch % account.period);
        
        return {
          key: account.key,
          name: account.name,
          code: token,
          algorithm: account.algorithm,
          timeRemaining: timeRemaining
        };
      } catch (err) {
        return {
          key: account.key,
          name: account.name,
          error: 'Failed to generate code'
        };
      }
    });
    
    res.json({ codes });
  } catch (err) {
    console.error('Error fetching codes:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// 3. Add new account (for easy setup)
app.post('/api/accounts', async (req, res) => {
  try {
    const { key, name, secret, digits, period, algorithm, type, counter, encrypt: shouldEncrypt } = req.body;
    
    if (!key || !secret) {
      return res.status(400).json({ error: 'key and secret are required' });
    }
    
    // Check if account already exists
    const existingAccount = await Account.findByKey(key);
    if (existingAccount) {
      return res.status(409).json({ error: 'Account already exists' });
    }
    
    // Normalize algorithm
    const normalizedAlgorithm = (algorithm || 'sha1').toLowerCase();
    
    // Validate secret by trying to generate a code
    try {
      speakeasy.totp({
        secret: secret,
        encoding: 'base32',
        algorithm: normalizedAlgorithm
      });
    } catch (err) {
      return res.status(400).json({ error: 'Invalid secret key' });
    }
    
    // Create new account
    const newAccount = new Account({
      key: key,
      name: name || key,
      secret: shouldEncrypt ? encrypt(secret) : secret,
      encrypted: shouldEncrypt || false,
      digits: digits || 6,
      period: period || 30,
      algorithm: normalizedAlgorithm,
      type: type || 'totp',
      counter: counter || 0
    });
    
    await newAccount.save();
    
    res.status(201).json({
      message: 'Account added successfully',
      key: newAccount.key,
      name: newAccount.name,
      algorithm: newAccount.algorithm
    });
  } catch (err) {
    console.error('Error adding account:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// 4. List all accounts (without secrets)
app.get('/api/accounts', async (req, res) => {
  try {
    const accounts = await Account.find({}, '-secret').lean();
    
    const accountList = accounts.map(account => ({
      key: account.key,
      name: account.name,
      digits: account.digits,
      period: account.period,
      algorithm: account.algorithm,
      type: account.type,
      encrypted: account.encrypted,
      createdAt: account.createdAt,
      updatedAt: account.updatedAt
    }));
    
    res.json({
      accounts: accountList,
      total: accountList.length
    });
  } catch (err) {
    console.error('Error listing accounts:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// 5. Update account
app.put('/api/accounts/:key', async (req, res) => {
  try {
    const { key } = req.params;
    const { name, secret, digits, period, algorithm, encrypt: shouldEncrypt } = req.body;
    
    const account = await Account.findByKey(key);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    // Update fields
    if (name) account.name = name;
    if (digits) account.digits = digits;
    if (period) account.period = period;
    if (algorithm) account.algorithm = algorithm.toLowerCase();
    
    if (secret) {
      account.secret = shouldEncrypt ? encrypt(secret) : secret;
      account.encrypted = shouldEncrypt || false;
    }
    
    await account.save();
    
    res.json({
      message: 'Account updated successfully',
      key: account.key,
      name: account.name
    });
  } catch (err) {
    console.error('Error updating account:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// 6. Delete account
app.delete('/api/accounts/:key', async (req, res) => {
  try {
    const { key } = req.params;
    
    const account = await Account.findOneAndDelete({ key: key });
    
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    res.json({
      message: 'Account deleted successfully',
      key: key
    });
  } catch (err) {
    console.error('Error deleting account:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    const count = await Account.countDocuments();
    res.json({ 
      status: 'ok',
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      accounts: count,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      error: err.message
    });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`\n🔐 Personal MFA Code Generator`);
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`💾 Database: ${MONGODB_URI}`);
  
  try {
    const count = await Account.countDocuments();
    console.log(`\n📋 Quick Start:`);
    console.log(`   GET  /api/code/:accountKey  - Get MFA code for Tines`);
    console.log(`   GET  /api/codes             - Get all codes`);
    console.log(`   POST /api/accounts          - Add new account`);
    console.log(`   PUT  /api/accounts/:key     - Update account`);
    console.log(`\n💡 Example Tines usage:`);
    console.log(`   curl http://localhost:${PORT}/api/code/google`);
    console.log(`\n📊 Total accounts in database: ${count}`);
    
    if (count > 0) {
      const accounts = await Account.find({}, 'key name').limit(5).lean();
      console.log(`   Recent: ${accounts.map(a => a.key).join(', ')}`);
    }
  } catch (err) {
    console.error('Error fetching account info:', err);
  }
  
  console.log('');
});