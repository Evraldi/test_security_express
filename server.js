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
// const errorMiddleware = require('./middlewares/errorMiddleware');
const authRoutes = require('./routes/authRoutes');

dotenv.config();

const app = express();

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

const isProduction = process.env.NODE_ENV === 'production';

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, 'https://trusted-cdn.com'],
      styleSrc: ["'self'", 'https://trusted-cdn.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https://fonts.example.com'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  frameguard: {
    action: 'deny',
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  xssFilter: true,
  noSniff: true,
}));

app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

app.post('/csp-violation-report', express.json({ type: ['json', 'application/csp-report'] }), (req, res) => {
  console.log('CSP Violation:', req.body);
  res.status(204).end();
});

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  credentials: true,
}));

app.use(hpp());
app.use(compression());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});

app.use((req, res, next) => {
  console.log('Request Headers:', req.headers);
  console.log('Request Cookies:', req.cookies);
  console.log('CSRF Token in Request:', req.headers['x-csrf-token']);
  console.log('CSRF Token from Cookies:', req.cookies['XSRF-TOKEN']);
  next();
});

app.use((req, res, next) => {
  console.log(`Incoming request: ${req.method} ${req.url}`);
  next();
});

const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'None' : 'Lax',
  },
});

app.use(csrfProtection);
app.use((req, res, next) => {
  const csrfToken = req.csrfToken();
  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false,
    secure: isProduction,
    sameSite: isProduction ? 'None' : 'Lax',
  });
  res.locals.csrfToken = csrfToken;
  next();
});

app.use('/api/auth', authLimiter, csrfProtection, authRoutes);

// app.use(errorMiddleware);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
