// config/env/test.js
require('dotenv').config();

describe('Environment Variables', () => {
  it('should have DATABASE_URL defined', () => {
    expect(process.env.DATABASE_URL).toBeDefined();
  });

  it('should have PRIVATE_KEY_PATH defined', () => {
    expect(process.env.PRIVATE_KEY_PATH).toBeDefined();
  });

  it('should have JWT_PASSPHRASE defined', () => {
    expect(process.env.JWT_PASSPHRASE).toBeDefined();
  });
});
