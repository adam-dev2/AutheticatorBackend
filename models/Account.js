// models/Account.js
const mongoose = require('mongoose');

const accountSchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  secret: {
    type: String,
    required: true
  },
  encrypted: {
    type: Boolean,
    default: false
  },
  digits: {
    type: Number,
    default: 6,
    min: 6,
    max: 8
  },
  period: {
    type: Number,
    default: 30,
    min: 15,
    max: 60
  },
  algorithm: {
    type: String,
    default: 'sha1',
    lowercase: true,
    enum: ['sha1', 'sha256', 'sha512']
  },
  type: {
    type: String,
    default: 'totp',
    lowercase: true,
    enum: ['totp', 'hotp']
  },
  counter: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true // Automatically adds createdAt and updatedAt
});

// Index for faster queries
accountSchema.index({ key: 1 });

// Method to generate TOTP code
accountSchema.methods.generateCode = function(speakeasy, decrypt, ENCRYPTION_KEY) {
  let secret = this.secret;
  
  // Decrypt if needed
  if (this.encrypted) {
    const parts = secret.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const crypto = require('crypto');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    secret = decrypted.toString();
  }
  
  // Generate token
  const token = speakeasy.totp({
    secret: secret,
    encoding: 'base32',
    algorithm: this.algorithm,
    digits: this.digits,
    step: this.period,
    window: 0
  });
  
  // Calculate time remaining
  const epoch = Math.round(new Date().getTime() / 1000.0);
  const timeRemaining = this.period - (epoch % this.period);
  
  return {
    code: token,
    timeRemaining: timeRemaining,
    expiresAt: new Date(Date.now() + (timeRemaining * 1000)).toISOString()
  };
};

// Static method to find account by key
accountSchema.statics.findByKey = function(key) {
  return this.findOne({ key: key });
};

module.exports = mongoose.model('Account', accountSchema);