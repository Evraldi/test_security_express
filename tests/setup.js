require('dotenv').config();

// Setup test environment
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-for-testing-purposes-only';
process.env.JWT_PASSPHRASE = 'test-passphrase';
process.env.DATABASE_URL = 'mysql://fake:fake@localhost:3306/testdb';

// Mock fs for key files
const fs = require('fs');
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockImplementation((path) => {
    if (path === process.env.PRIVATE_KEY_PATH || path === process.env.PUBLIC_KEY_PATH) {
      return 'MOCK_KEY_CONTENT';
    }
    return jest.requireActual('fs').readFileSync(path);
  }),
}));

// Mock bcrypt for faster tests
jest.mock('bcrypt', () => ({
  hash: jest.fn().mockImplementation((password) => Promise.resolve(`hashed_${password}`)),
  compare: jest.fn().mockImplementation((password, hash) => {
    // For testing, we'll consider a password valid if it contains 'valid'
    return Promise.resolve(password.includes('valid') || password === 'Password123!');
  }),
}));

// Don't mock crypto completely as it breaks CSRF
// Instead, just spy on the methods we want to control
const crypto = jest.requireActual('crypto');
jest.spyOn(crypto, 'randomBytes').mockImplementation((size) => {
  return {
    toString: () => 'test-nonce-value'
  };
});

// Tidak perlu afterAll di sini karena ini bukan file test
// Kita hanya perlu setup environment
