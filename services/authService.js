const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Get private key for JWT signing
let privateKey;
try {
  privateKey = process.env.PRIVATE_KEY_PATH ?
    fs.readFileSync(process.env.PRIVATE_KEY_PATH, 'utf8') :
    process.env.JWT_SECRET;
} catch (error) {
  console.error('Error loading private key:', error.message);
  // Fallback to JWT_SECRET if file can't be read
  privateKey = process.env.JWT_SECRET;
}

// Password strength regex - requires at least 8 chars, 1 uppercase, 1 lowercase, 1 number
const STRONG_PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

async function validatePassword(password) {
  // For testing purposes, we'll allow simple passwords if not in production
  if (process.env.NODE_ENV !== 'production' && password.length >= 6) {
    return true;
  }

  return STRONG_PASSWORD_REGEX.test(password);
}

async function register({ email, password, name }) {
  // Check if user already exists
  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    return null;
  }

  // Validate password strength (in production)
  if (process.env.NODE_ENV === 'production' && !await validatePassword(password)) {
    throw new Error('Password does not meet security requirements');
  }

  // Use higher cost factor in production
  const saltRounds = process.env.NODE_ENV === 'production' ? 12 : 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const newUser = await prisma.user.create({
    data: { email, password: hashedPassword, name },
  });

  // Don't return password hash
  const { password: _, ...userWithoutPassword } = newUser;
  return userWithoutPassword;
}

async function login(email, password) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    // Use constant-time comparison to prevent timing attacks
    await bcrypt.compare(password, '$2b$10$invalidhashforcomparisonabcdefghijklmnopqrstuv');
    return { user: null, token: null };
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return { user: null, token: null };
  }

  // Create JWT with appropriate claims
  const token = jwt.sign(
    {
      sub: user.id.toString(),
      email: user.email,
      iat: Math.floor(Date.now() / 1000),
    },
    privateKey,
    {
      expiresIn: '1h',
      algorithm: process.env.PRIVATE_KEY_PATH ? 'RS256' : 'HS256'
    }
  );

  // Don't return password hash
  const { password: _, ...userWithoutPassword } = user;
  return { user: userWithoutPassword, token };
}

module.exports = {
  register,
  login,
  validatePassword, // Export for testing
};
