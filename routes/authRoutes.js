const express = require('express');
const { body, validationResult } = require('express-validator');
const { register, login, logout } = require('../controllers/authController');
const rateLimit = require('express-rate-limit');
const authMiddleware = require('../middlewares/authMiddleware');

const router = express.Router();

/**
 * Enhanced validation rules with stronger security checks
 */
const validationRules = {
  register: [
    body('email')
      .isEmail().withMessage('Invalid email format')
      .normalizeEmail({ gmail_remove_dots: false }) // Less aggressive normalization
      .trim()
      .isLength({ max: 100 }).withMessage('Email is too long')
      .escape(),

    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage(
        'Password must contain at least one uppercase letter, one lowercase letter, and one number'
      )
      .not().matches(/^(.*)\1{2,}/).withMessage('Password cannot contain repeated patterns')
      .not().matches(/password/i).withMessage('Password cannot contain the word "password"')
      .trim()
      .escape(),

    body('name')
      .notEmpty().withMessage('Name is required')
      .trim()
      .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters')
      .matches(/^[a-zA-Z0-9 ]*$/)
      .withMessage('Name can only contain letters, numbers, and spaces')
      .escape(),
  ],

  login: [
    body('email')
      .isEmail().withMessage('Invalid email format')
      .normalizeEmail({ gmail_remove_dots: false })
      .trim()
      .escape(),

    body('password')
      .notEmpty().withMessage('Password is required')
      .isLength({ min: 1, max: 100 }).withMessage('Invalid password length')
      .trim()
      .escape(),
  ],
};

/**
 * Validation middleware that returns standardized error responses
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

// Login attempt limiter - stricter than the global one
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 'error',
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
  },
  skipSuccessfulRequests: true // Don't count successful logins against the limit
});

// Debug logging only in development
if (process.env.NODE_ENV !== 'production') {
  router.use((req, res, next) => {
    console.log('Auth route accessed:', req.path);
    console.log('CSRF Token in Request:', req.headers['x-csrf-token']);
    next();
  });
}

// Routes
router.post('/register', validationRules.register, validate, register);
router.post('/login', loginLimiter, validationRules.login, validate, login);
router.post('/logout', authMiddleware, logout);

// Protected route for testing authentication
router.get('/protected', authMiddleware, (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'You are authenticated',
    user: req.user
  });
});

// CSRF token endpoint
router.get('/csrf-token', (req, res) => {
  const csrfToken = req.csrfToken();
  const isProduction = process.env.NODE_ENV === 'production';

  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false, // Must be accessible to JS
    secure: isProduction,
    sameSite: isProduction ? 'Strict' : 'Lax',
    maxAge: 3600000 // 1 hour
  });

  res.json({ csrfToken });
});

module.exports = router;
