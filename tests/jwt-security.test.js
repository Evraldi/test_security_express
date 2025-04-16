const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Generate test keys
const generateTestKeys = () => {
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
      passphrase: 'test-passphrase'
    }
  });
  
  return { privateKey, publicKey, passphrase: 'test-passphrase' };
};

describe('JWT Security', () => {
  let keys;
  
  beforeAll(() => {
    keys = generateTestKeys();
  });
  
  describe('Token Generation', () => {
    it('should generate a valid JWT with proper claims', () => {
      const payload = {
        sub: '123',
        email: 'test@example.com',
        iat: Math.floor(Date.now() / 1000)
      };
      
      const token = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256',
        expiresIn: '1h'
      });
      
      expect(token).toBeDefined();
      expect(token.split('.')).toHaveLength(3); // Header, payload, signature
    });
    
    it('should include standard security claims', () => {
      const payload = {
        sub: '123',
        email: 'test@example.com',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
        aud: 'test-app',
        iss: 'test-issuer'
      };
      
      const token = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256'
      });
      
      const decoded = jwt.decode(token);
      
      expect(decoded).toHaveProperty('sub', '123');
      expect(decoded).toHaveProperty('iat');
      expect(decoded).toHaveProperty('exp');
      expect(decoded).toHaveProperty('aud', 'test-app');
      expect(decoded).toHaveProperty('iss', 'test-issuer');
    });
  });
  
  describe('Token Verification', () => {
    it('should verify a valid token', () => {
      const payload = { sub: '123', email: 'test@example.com' };
      const token = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256',
        expiresIn: '1h'
      });
      
      const verified = jwt.verify(token, keys.publicKey, { algorithms: ['RS256'] });
      
      expect(verified).toHaveProperty('sub', '123');
      expect(verified).toHaveProperty('email', 'test@example.com');
    });
    
    it('should reject an expired token', () => {
      const payload = { sub: '123', email: 'test@example.com' };
      const token = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256',
        expiresIn: '-10s' // Expired 10 seconds ago
      });
      
      expect(() => {
        jwt.verify(token, keys.publicKey, { algorithms: ['RS256'] });
      }).toThrow(/jwt expired/);
    });
    
    it('should reject a token with invalid signature', () => {
      const payload = { sub: '123', email: 'test@example.com' };
      const token = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256'
      });
      
      // Generate a different key pair
      const { publicKey: differentPublicKey } = generateTestKeys();
      
      expect(() => {
        jwt.verify(token, differentPublicKey, { algorithms: ['RS256'] });
      }).toThrow(/invalid signature/);
    });
    
    it('should reject a token with wrong algorithm', () => {
      const payload = { sub: '123', email: 'test@example.com' };
      const token = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256'
      });
      
      expect(() => {
        jwt.verify(token, keys.publicKey, { algorithms: ['HS256'] });
      }).toThrow(/invalid algorithm/);
    });
  });
  
  describe('Token Security Best Practices', () => {
    it('should not include sensitive information in payload', () => {
      const payload = {
        sub: '123',
        email: 'test@example.com',
        role: 'user'
      };
      
      const token = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256'
      });
      
      const decoded = jwt.decode(token);
      
      // These should be included
      expect(decoded).toHaveProperty('sub');
      expect(decoded).toHaveProperty('email');
      expect(decoded).toHaveProperty('role');
      
      // These should NOT be included
      expect(decoded).not.toHaveProperty('password');
      expect(decoded).not.toHaveProperty('creditCard');
      expect(decoded).not.toHaveProperty('ssn');
    });
    
    it('should use asymmetric keys (RS256) instead of symmetric keys (HS256) for better security', () => {
      const payload = { sub: '123', email: 'test@example.com' };
      
      // Sign with RS256 (asymmetric)
      const tokenRS256 = jwt.sign(payload, { key: keys.privateKey, passphrase: keys.passphrase }, { 
        algorithm: 'RS256'
      });
      
      // Verify with public key
      const verifiedRS256 = jwt.verify(tokenRS256, keys.publicKey, { algorithms: ['RS256'] });
      expect(verifiedRS256).toHaveProperty('sub', '123');
      
      // This should fail - can't verify with private key
      expect(() => {
        jwt.verify(tokenRS256, 'some-secret-key', { algorithms: ['HS256'] });
      }).toThrow();
    });
  });
});
