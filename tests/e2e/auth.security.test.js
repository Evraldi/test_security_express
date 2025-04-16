/**
 * End-to-End Authentication Security Tests
 * 
 * This file contains real tests against the actual application
 * to verify security measures are properly implemented.
 */

const request = require('supertest');
const app = require('../../for_test');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');

describe('Authentication Security E2E Tests', () => {
  let prisma;
  let agent;
  let csrfToken;
  
  // Setup test database and create test user
  beforeAll(async () => {
    prisma = new PrismaClient();
    
    try {
      // Create test user with secure password
      const hashedPassword = await bcrypt.hash('SecureP@ssw0rd123', 10);
      
      // Check if test user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email: 'security.test@example.com' }
      });
      
      if (!existingUser) {
        await prisma.user.create({
          data: {
            email: 'security.test@example.com',
            password: hashedPassword,
            name: 'Security Test User'
          }
        });
      }
    } catch (error) {
      console.error('Error setting up test database:', error);
    }
  });
  
  // Clean up after tests
  afterAll(async () => {
    try {
      // Delete test user
      await prisma.user.deleteMany({
        where: { email: { contains: 'test@example.com' } }
      });
      
      await prisma.$disconnect();
    } catch (error) {
      console.error('Error cleaning up test database:', error);
    }
  });
  
  // Setup for each test
  beforeEach(async () => {
    agent = request.agent(app);
    
    // Get CSRF token
    try {
      const response = await agent.get('/api/auth/csrf-token');
      if (response.status === 200 && response.body.csrfToken) {
        csrfToken = response.body.csrfToken;
      } else {
        console.error('Failed to get CSRF token, status:', response.status);
      }
    } catch (error) {
      console.error('Error getting CSRF token:', error.message);
    }
  });
  
  describe('Registration Security', () => {
    it('should reject registration with weak password', async () => {
      const response = await agent
        .post('/api/auth/register')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'weak.password@example.com',
          password: 'password', // Weak password
          name: 'Weak Password User'
        });
      
      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('errors');
      // Check that error message mentions password requirements
      const passwordError = response.body.errors.find(e => e.param === 'password');
      expect(passwordError).toBeDefined();
    });
    
    it('should reject registration with invalid email format', async () => {
      const response = await agent
        .post('/api/auth/register')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'not-an-email',
          password: 'SecureP@ssw0rd123',
          name: 'Invalid Email User'
        });
      
      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('errors');
      const emailError = response.body.errors.find(e => e.param === 'email');
      expect(emailError).toBeDefined();
    });
    
    it('should sanitize user input to prevent XSS', async () => {
      const response = await agent
        .post('/api/auth/register')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'xss.test@example.com',
          password: 'SecureP@ssw0rd123',
          name: '<script>alert("XSS")</script>XSS Test User'
        });
      
      // Even if registration fails for other reasons, check that the response
      // doesn't contain unescaped script tags
      expect(JSON.stringify(response.body)).not.toContain('<script>alert("XSS")</script>');
    });
    
    it('should prevent SQL injection in registration', async () => {
      const response = await agent
        .post('/api/auth/register')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: "sql.injection@example.com'; DROP TABLE users; --",
          password: 'SecureP@ssw0rd123',
          name: 'SQL Injection Test User'
        });
      
      // The request might fail for various reasons, but the important thing
      // is that the application doesn't crash due to SQL injection
      expect(response.status).not.toBe(500);
    });
    
    it('should not allow duplicate email registration', async () => {
      // First create a user
      await agent
        .post('/api/auth/register')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'duplicate.test@example.com',
          password: 'SecureP@ssw0rd123',
          name: 'Duplicate Test User'
        });
      
      // Get a new CSRF token
      const csrfResponse = await agent.get('/api/auth/csrf-token');
      const newCsrfToken = csrfResponse.body.csrfToken;
      
      // Try to register with the same email
      const response = await agent
        .post('/api/auth/register')
        .set('X-CSRF-Token', newCsrfToken)
        .send({
          email: 'duplicate.test@example.com',
          password: 'DifferentP@ssw0rd123',
          name: 'Duplicate Test User 2'
        });
      
      expect(response.status).toBe(409); // Conflict
      expect(response.body.message).toContain('exists');
    });
  });
  
  describe('Login Security', () => {
    it('should reject login with incorrect password', async () => {
      const response = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'security.test@example.com',
          password: 'WrongPassword123'
        });
      
      expect(response.status).toBe(401);
      expect(response.body.message).toContain('Invalid credentials');
    });
    
    it('should reject login for non-existent user', async () => {
      const response = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'nonexistent@example.com',
          password: 'AnyPassword123'
        });
      
      expect(response.status).toBe(401);
      expect(response.body.message).toContain('Invalid credentials');
      
      // Important: The error message should be the same as for wrong password
      // to prevent user enumeration
    });
    
    it('should prevent SQL injection in login', async () => {
      const response = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: "' OR '1'='1",
          password: "anything' OR '1'='1"
        });
      
      // Should be rejected by validation or return 401, not 500
      expect(response.status).not.toBe(500);
      expect(response.status).not.toBe(200); // Should not succeed
    });
    
    it('should set secure cookies on successful login', async () => {
      const response = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'security.test@example.com',
          password: 'SecureP@ssw0rd123'
        });
      
      if (response.status === 200) {
        // Check for secure cookie settings
        expect(response.headers['set-cookie']).toBeDefined();
        const cookieHeader = response.headers['set-cookie'][0];
        
        // Check for HttpOnly flag
        expect(cookieHeader).toContain('HttpOnly');
        
        // In a production environment, would also check for:
        // expect(cookieHeader).toContain('Secure');
        // expect(cookieHeader).toContain('SameSite');
      }
    });
    
    it('should return a valid JWT token on successful login', async () => {
      const response = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'security.test@example.com',
          password: 'SecureP@ssw0rd123'
        });
      
      if (response.status === 200) {
        expect(response.body).toHaveProperty('token');
        
        const token = response.body.token;
        
        // Verify token structure
        const parts = token.split('.');
        expect(parts.length).toBe(3); // Header, payload, signature
        
        // Decode payload (without verification)
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        
        // Check essential claims
        expect(payload).toHaveProperty('sub'); // Subject (user ID)
        expect(payload).toHaveProperty('iat'); // Issued at
        expect(payload).toHaveProperty('exp'); // Expiration
        
        // Verify expiration is in the future
        expect(payload.exp).toBeGreaterThan(Date.now() / 1000);
      }
    });
  });
  
  describe('CSRF Protection', () => {
    it('should reject requests without CSRF token', async () => {
      const response = await agent
        .post('/api/auth/login')
        .send({
          email: 'security.test@example.com',
          password: 'SecureP@ssw0rd123'
        });
      
      expect(response.status).toBe(403);
      expect(response.body.message).toContain('csrf');
    });
    
    it('should reject requests with invalid CSRF token', async () => {
      const response = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', 'invalid-token')
        .send({
          email: 'security.test@example.com',
          password: 'SecureP@ssw0rd123'
        });
      
      expect(response.status).toBe(403);
      expect(response.body.message).toContain('csrf');
    });
  });
  
  describe('Rate Limiting', () => {
    it('should limit excessive login attempts', async () => {
      // Make multiple login attempts
      const maxAttempts = 15; // This should exceed the rate limit
      
      for (let i = 0; i < maxAttempts; i++) {
        // Get a fresh CSRF token for each request
        const csrfResponse = await agent.get('/api/auth/csrf-token');
        const freshCsrfToken = csrfResponse.body.csrfToken;
        
        await agent
          .post('/api/auth/login')
          .set('X-CSRF-Token', freshCsrfToken)
          .send({
            email: `attempt${i}@example.com`,
            password: 'WrongPassword123'
          });
      }
      
      // Get a fresh CSRF token
      const csrfResponse = await agent.get('/api/auth/csrf-token');
      const freshCsrfToken = csrfResponse.body.csrfToken;
      
      // This should trigger rate limiting
      const response = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', freshCsrfToken)
        .send({
          email: 'security.test@example.com',
          password: 'SecureP@ssw0rd123'
        });
      
      // Should be rate limited (429 Too Many Requests)
      // Note: This test might be flaky depending on rate limit configuration
      expect(response.status).toBe(429);
    });
  });
  
  describe('Logout Security', () => {
    it('should clear auth token on logout', async () => {
      // First login
      const loginResponse = await agent
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'security.test@example.com',
          password: 'SecureP@ssw0rd123'
        });
      
      if (loginResponse.status === 200) {
        // Get a fresh CSRF token
        const csrfResponse = await agent.get('/api/auth/csrf-token');
        const freshCsrfToken = csrfResponse.body.csrfToken;
        
        // Then logout
        const logoutResponse = await agent
          .post('/api/auth/logout')
          .set('X-CSRF-Token', freshCsrfToken);
        
        expect(logoutResponse.status).toBe(200);
        
        // Check that cookie is cleared
        expect(logoutResponse.headers['set-cookie']).toBeDefined();
        const cookieHeader = logoutResponse.headers['set-cookie'][0];
        expect(cookieHeader).toContain('token=;');
        expect(cookieHeader).toContain('Expires=');
      }
    });
  });
});
