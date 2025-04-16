const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

// Mock modules before importing the service
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockImplementation((path) => {
    if (path.includes('private.pem') || path.includes('public.pem')) {
      return 'MOCK_KEY_CONTENT';
    }
    return jest.requireActual('fs').readFileSync(path);
  }),
}));

// Mock PrismaClient
jest.mock('@prisma/client', () => {
  const mockPrismaClient = {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
    $connect: jest.fn(),
    $disconnect: jest.fn(),
  };
  return { PrismaClient: jest.fn(() => mockPrismaClient) };
});

// Mock bcrypt
jest.mock('bcrypt', () => ({
  hash: jest.fn().mockImplementation((password, saltRounds) => Promise.resolve(`hashed_${password}`)),
  compare: jest.fn().mockImplementation((password, hash) => Promise.resolve(password === 'Password123!')),
}));

// Mock jwt
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn().mockReturnValue('mock.jwt.token'),
  verify: jest.fn().mockReturnValue({ sub: '1', email: 'test@example.com' }),
}));

// Import the service after mocking
const authService = require('../services/authService');

describe('JWT Authentication', () => {
  // Get the mocked PrismaClient instance
  const prisma = new (require('@prisma/client').PrismaClient)();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Password Validation', () => {
    it('should validate strong passwords', async () => {
      const result = await authService.validatePassword('StrongP@ss123');
      expect(result).toBe(true);
    });

    it('should reject weak passwords in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const result = await authService.validatePassword('weak');

      expect(result).toBe(false);

      // Restore environment
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('User Registration', () => {
    it('should hash passwords during registration', async () => {
      // Setup mocks
      const prisma = new (require('@prisma/client').PrismaClient)();
      prisma.user.findUnique.mockResolvedValueOnce(null);
      prisma.user.create.mockResolvedValueOnce({
        id: 1,
        email: 'test@example.com',
        name: 'Test User',
        password: 'hashed_password',
      });

      // Call the function
      const result = await authService.register({
        email: 'test@example.com',
        password: 'Password123!',
        name: 'Test User',
      });

      // Verify user was created
      expect(prisma.user.create).toHaveBeenCalled();
      expect(result).toHaveProperty('email', 'test@example.com');
      expect(result).not.toHaveProperty('password');
    });
  });

  describe('User Login', () => {
    it('should generate a JWT token on successful login', async () => {
      // Setup mocks
      const prisma = new (require('@prisma/client').PrismaClient)();
      prisma.user.findUnique.mockResolvedValueOnce({
        id: 1,
        email: 'test@example.com',
        password: 'hashed_password',
        name: 'Test User',
      });

      // Call the function
      const result = await authService.login('test@example.com', 'Password123!');

      // Verify JWT was generated
      expect(result).toHaveProperty('token', 'mock.jwt.token');
    });

    it('should not return password hash in user object', async () => {
      // Setup mocks
      const prisma = new (require('@prisma/client').PrismaClient)();
      prisma.user.findUnique.mockResolvedValueOnce({
        id: 1,
        email: 'test@example.com',
        password: 'hashed_password',
        name: 'Test User',
      });

      // Call the function
      const result = await authService.login('test@example.com', 'Password123!');

      // Verify password is not returned
      expect(result.user).not.toHaveProperty('password');
    });
  });
});
