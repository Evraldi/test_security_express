const request = require('supertest');
const express = require('express');
const cookieParser = require('cookie-parser');

/**
 * Create a test app with cookie security features
 */
const createCookieSecurityApp = () => {
  const app = express();
  app.use(cookieParser());

  // Set secure cookie
  app.get('/set-secure-cookie', (req, res) => {
    res.cookie('secureSession', 'secure-value', {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 3600000, // 1 hour
      path: '/',
      domain: req.hostname,
    });
    res.status(200).json({ status: 'success' });
  });

  // Set insecure cookie (for testing purposes)
  app.get('/set-insecure-cookie', (req, res) => {
    res.cookie('insecureSession', 'insecure-value', {
      httpOnly: false,
      secure: false,
      maxAge: 3600000, // 1 hour
    });
    res.status(200).json({ status: 'success' });
  });

  // Set cookie with SameSite=None (for cross-origin requests)
  app.get('/set-cross-origin-cookie', (req, res) => {
    res.cookie('crossOriginSession', 'cross-origin-value', {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
      maxAge: 3600000, // 1 hour
    });
    res.status(200).json({ status: 'success' });
  });

  // Clear cookie
  app.get('/clear-cookie', (req, res) => {
    res.clearCookie('secureSession');
    res.status(200).json({ status: 'success' });
  });

  // Cookie info
  app.get('/cookie-info', (req, res) => {
    res.status(200).json({ cookies: req.cookies });
  });

  return app;
};

describe('Cookie Security', () => {
  let app;
  let agent;

  beforeAll(() => {
    app = createCookieSecurityApp();
    agent = request.agent(app);
  });

  describe('Secure Cookie Attributes', () => {
    it('should set cookies with secure attributes', async () => {
      const response = await request(app).get('/set-secure-cookie');

      expect(response.status).toBe(200);
      expect(response.headers['set-cookie']).toBeDefined();

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('secureSession=');
      expect(cookieHeader).toContain('HttpOnly');
      expect(cookieHeader).toContain('Secure');
      expect(cookieHeader).toContain('SameSite=Strict');
      expect(cookieHeader).toContain('Path=/');
      expect(cookieHeader).toContain('Max-Age=');
    });

    it('should identify insecure cookies', async () => {
      const response = await request(app).get('/set-insecure-cookie');

      expect(response.status).toBe(200);
      expect(response.headers['set-cookie']).toBeDefined();

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('insecureSession=');
      expect(cookieHeader).not.toContain('HttpOnly');
      expect(cookieHeader).not.toContain('Secure');
    });

    it('should set cross-origin cookies with appropriate attributes', async () => {
      const response = await request(app).get('/set-cross-origin-cookie');

      expect(response.status).toBe(200);
      expect(response.headers['set-cookie']).toBeDefined();

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('crossOriginSession=');
      expect(cookieHeader).toContain('HttpOnly');
      expect(cookieHeader).toContain('Secure');
      expect(cookieHeader).toContain('SameSite=None');
    });
  });

  describe('Cookie Management', () => {
    it('should properly clear cookies', async () => {
      // First set a cookie
      await agent.get('/set-secure-cookie');

      // Then clear it
      const response = await agent.get('/clear-cookie');

      expect(response.status).toBe(200);
      expect(response.headers['set-cookie']).toBeDefined();

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('secureSession=');
      expect(cookieHeader).toContain('Expires=');

      // Verify cookie is cleared
      const infoResponse = await agent.get('/cookie-info');
      expect(infoResponse.body.cookies).not.toHaveProperty('secureSession');
    });

    it('should maintain cookie state across requests with non-secure cookies', async () => {
      // Set a non-secure cookie (secure cookies won't be sent in tests due to lack of HTTPS)
      await agent.get('/set-insecure-cookie');

      // Check if cookie is present in subsequent request
      const response = await agent.get('/cookie-info');

      expect(response.status).toBe(200);
      expect(response.body.cookies).toHaveProperty('insecureSession', 'insecure-value');
    });
  });

  describe('Cookie Security Best Practices', () => {
    it('should use HttpOnly flag to prevent JavaScript access', async () => {
      const response = await request(app).get('/set-secure-cookie');

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('HttpOnly');
    });

    it('should use Secure flag to ensure HTTPS-only transmission', async () => {
      const response = await request(app).get('/set-secure-cookie');

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('Secure');
    });

    it('should use SameSite attribute to prevent CSRF', async () => {
      const response = await request(app).get('/set-secure-cookie');

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('SameSite=Strict');
    });

    it('should set appropriate expiration time', async () => {
      const response = await request(app).get('/set-secure-cookie');

      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('Max-Age=3600');
    });
  });
});
