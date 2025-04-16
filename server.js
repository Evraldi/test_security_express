const express = require('express');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const hpp = require('hpp');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const errorMiddleware = require('./middlewares/errorMiddleware');
const authRoutes = require('./routes/authRoutes');

// Load environment variables
dotenv.config();

const app = express();
const isProduction = process.env.NODE_ENV === 'production';

// Trust proxy if behind a reverse proxy (important for rate limiting and secure cookies)
if (isProduction) {
  app.set('trust proxy', 1);
}

// Generate nonce for CSP
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// Basic middleware setup
app.use(express.urlencoded({ extended: true, limit: '10kb' })); // Limit body size
app.use(express.json({ limit: '10kb' })); // Limit JSON payload size
app.use(cookieParser());

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"], // Consider removing unsafe-inline in production
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null,
      reportUri: '/csp-violation-report'
    },
    reportOnly: false,
  },
  frameguard: {
    action: 'deny',
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// CSP violation reporting endpoint
app.post('/csp-violation-report', express.json({
  type: ['json', 'application/csp-report', 'application/json'],
  limit: '10kb'
}), (req, res) => {
  const isProduction = process.env.NODE_ENV === 'production';
  if (isProduction) {
    // In production, consider logging to a secure logging service
    console.error('CSP Violation:', req.body);
  } else {
    console.log('CSP Violation:', req.body);
  }
  res.status(204).end();
});

// CORS configuration
app.use(cors({
  origin: isProduction ? process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000' : 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true,
  maxAge: 86400, // 24 hours
}));

// HTTP Parameter Pollution protection
app.use(hpp());

// Response compression
app.use(compression());

// Global rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isProduction ? 100 : 1000, // Limit each IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many requests, please try again later.' },
  skip: (req) => req.ip === '127.0.0.1' // Optional: don't rate limit local development
}));

// More aggressive rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isProduction ? 25 : 100, // Stricter limit for auth routes
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many authentication attempts, please try again later.' }
});

// Debug logging only in development
if (!isProduction) {
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
  });
}

// CSRF Protection
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'Strict' : 'Lax', // Use Strict in production
    maxAge: 3600, // 1 hour
  },
});

// Apply CSRF protection globally
app.use(csrfProtection);

// Set CSRF token cookie for frontend
app.use((req, res, next) => {
  const csrfToken = req.csrfToken();
  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false, // Needs to be accessible from JS
    secure: isProduction,
    sameSite: isProduction ? 'Strict' : 'Lax',
    maxAge: 3600000, // 1 hour in milliseconds
  });
  res.locals.csrfToken = csrfToken;
  next();
});

// Routes
app.use('/api/auth', authLimiter, authRoutes);

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ status: 'error', message: 'Resource not found' });
});

// Error handling middleware
app.use(errorMiddleware);

// Start server
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${port}`);
  });
}

module.exports = app;
