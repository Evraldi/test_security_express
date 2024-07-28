const express = require('express');
const { body, validationResult } = require('express-validator');
const { register, login } = require('../controllers/authController');

const router = express.Router();

const validationRules = {
  register: [
    body('email')
      .isEmail().withMessage('Invalid email format')
      .normalizeEmail()
      .escape(),
    body('password')
      .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
      .trim()
      .escape(),
    body('name')
      .notEmpty().withMessage('Name is required')
      .trim()
      .matches(/^[a-zA-Z0-9 ]*$/)
      .withMessage('Name contains invalid characters')
      .escape(),
  ],
  login: [
    body('email')
      .isEmail().withMessage('Invalid email format')
      .normalizeEmail()
      .escape(),
    body('password')
      .notEmpty().withMessage('Password is required')
      .trim()
      .escape(),
  ],
};

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.use((req, res, next) => {
  console.log('CSRF Token in Request:', req.headers['x-csrf-token']);
  console.log('CSRF Token from Cookies:', req.cookies['XSRF-TOKEN']);
  next();
});

router.post('/register', validationRules.register, validate, register);
router.post('/login', validationRules.login, validate, login);

router.get('/csrf-token', (req, res) => {
  const csrfToken = req.csrfToken();
  res.cookie('XSRF-TOKEN', csrfToken, { httpOnly: false });
  res.json({ csrfToken });
});

module.exports = router;
