const express = require('express');
const { connectDB, sequelize } = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const articleRoutes = require('./routes/articles');
require('dotenv').config();
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const xssClean = require('xss-clean');
const hpp = require('hpp');
const morgan = require('morgan');
const compression = require('compression');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5001;

connectDB();

sequelize.sync()
  .then(() => console.log('Database synced...'))
  .catch(err => console.error('Error syncing database:', err));

app.use(helmet());

const corsOptions = {
  origin: (origin, callback) => {
    if (['http://localhost:3000'].includes(origin) || !origin) {
      // Allow requests from localhost or no origin (e.g., Postman)
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));


// Rate limiter for development
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again after 15 minutes'
});
app.use(limiter);

app.use(xssClean());

app.use(hpp());

app.use(compression());

app.use(morgan('dev'));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());

const csrfProtection = csurf({
  cookie: {
    httpOnly: false,
    secure: false,
    sameSite: 'Lax',
  }
});

app.use(csrfProtection);
app.use((req, res, next) => {
  const csrfToken = req.csrfToken();
  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false,
    secure: false,
    sameSite: 'Lax',
  });
  res.locals.csrfToken = csrfToken;
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self';");
  next();
});

app.use('/api/articles', articleRoutes);
app.use('/api/auth', authRoutes);

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('Invalid CSRF Token');
  }
  console.error('Error occurred:', err.stack);
  res.status(500).send('Something broke!');
});

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT} at ${new Date().toISOString()}`);
});