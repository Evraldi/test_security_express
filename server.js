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
const PORT = process.env.PORT || 5001;  //might change

connectDB();

sequelize.sync()
  .then(() => console.log('Database synced...'))
  .catch(err => console.error('Error syncing database:', err));

const isProduction = process.env.NODE_ENV === 'production';

// Helmet configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
    },
  },
  frameguard: { action: 'deny' },
  hsts: isProduction ? { maxAge: 31536000, includeSubDomains: true } : false, // HSTS false in development
  xssFilter: true,
  noSniff: true,
}));

// CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [process.env.CLIENT_URL];
    if (allowedOrigins.includes(origin) || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again after 15 minutes'
});

if (!isProduction) {
  app.use(limiter); // test
}

app.use(xssClean());
app.use(hpp());
app.use(compression());
app.use(morgan(isProduction ? 'combined' : 'dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const csrfProtection = csurf({
  cookie: {
    httpOnly: true, // Prevents client-side JavaScript from accessing the CSRF cookie
    secure: isProduction,
    sameSite: isProduction ? 'None' : 'Lax',
  },
});

app.use(csrfProtection);
app.use((req, res, next) => {
  const csrfToken = req.csrfToken();
  res.cookie('XSRF-TOKEN', csrfToken, {
    httpOnly: false,  // Allows client-side JavaScript to access the CSRF token
    secure: isProduction,
    sameSite: isProduction ? 'None' : 'Lax',
  });
  res.locals.csrfToken = csrfToken;
  next();
});

// Routes
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
