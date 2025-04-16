const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Get passphrase from .env or use default
const passphrase = process.env.JWT_PASSPHRASE || 'your-secure-passphrase';

console.log('Generating RSA key pair for JWT...');

// Generate key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase
  }
});

// Save private key
fs.writeFileSync(path.join(__dirname, 'private.pem'), privateKey);
console.log('Private key saved to private.pem');

// Save public key
fs.writeFileSync(path.join(__dirname, 'public.pem'), publicKey);
console.log('Public key saved to public.pem');

console.log('Key pair generated successfully!');
console.log(`Passphrase: ${passphrase} (stored in .env as JWT_PASSPHRASE)`);
