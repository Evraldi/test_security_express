const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const User = require('../models/User');
const LoginAttempt = require('../models/LoginAttempt');

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 login attempts per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
});

exports.login = [
  loginLimiter, // Apply rate limiting to login route
  body('email').isEmail().withMessage('Invalid email address'),
  body('password').not().isEmpty().withMessage('Password is required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
        message: 'Validation errors occurred'
      });
    }

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      const token = jwt.sign(
        { id: user.id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' } // Consider a shorter expiry and use refresh tokens
      );

      res.json({
        success: true,
        token
      });
    } catch (err) {
      console.error('Server Error:', err.message);
      res.status(500).json({
        success: false,
        message: 'An unexpected server error occurred. Please try again later.',
        error: err.message
      });
    }
  }
];


exports.register = [
  body('email').isEmail().withMessage('Invalid email address').normalizeEmail(),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-zA-Z]).{8,}/).withMessage('Password must contain at least one number, one special character, and one letter'),
  body('username').notEmpty().withMessage('Username is required').trim().escape(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
        message: 'Validation errors occurred'
      });
    }

    const { username, password, email } = req.body;

    try {
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Email is already in use'
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = await User.create({ username, password: hashedPassword, email });

      res.status(201).json({
        success: true,
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email
        }
      });
    } catch (err) {
      console.error('Server error in register:', err);
      res.status(500).json({
        success: false,
        message: 'An unexpected server error occurred. Please try again later.',
        error: err.message
      });
    }
  }
];

exports.forgotPassword = [
  body('email').isEmail().withMessage('Invalid email address').normalizeEmail(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
        message: 'Validation errors occurred'
      });
    }

    const { email } = req.body;

    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      if (user.resetToken && user.resetTokenExpiry > Date.now()) {
        return res.status(400).json({
          success: false,
          message: 'A reset request is already pending. Please wait or check your email.'
        });
      }

      const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      user.resetToken = resetToken;
      user.resetTokenExpiry = new Date(Date.now() + 3600000);
      await user.save();

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset',
        text: `Click the link to reset your password: ${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to send password reset email. Please try again later.'
          });
        }
        res.json({
          success: true,
          message: 'Password reset email sent. Please check your inbox.'
        });
      });
    } catch (err) {
      console.error('Error in forgotPassword:', err);
      res.status(500).json({
        success: false,
        message: 'An unexpected server error occurred. Please try again later.',
        error: err.message
      });
    }
  }
];

exports.resetPassword = [
  body('token').notEmpty().withMessage('Token is required'),
  body('newPassword')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-zA-Z]).{8,}/).withMessage('Password must contain at least one number, one special character, and one letter'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
        message: 'Validation errors occurred'
      });
    }

    const { token, newPassword } = req.body;

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (!decoded || !decoded.id) {
        return res.status(400).json({
          success: false,
          message: 'Invalid token'
        });
      }

      const user = await User.findByPk(decoded.id);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      if (user.resetToken !== token || user.resetTokenExpiry < Date.now()) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired token'
        });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.resetToken = null;
      user.resetTokenExpiry = null;
      await user.save();

      res.json({
        success: true,
        message: 'Password has been successfully reset'
      });
    } catch (err) {
      console.error('Error in resetPassword:', err);
      res.status(500).json({
        success: false,
        message: 'An unexpected server error occurred. Please try again later.',
        error: err.message
      });
    }
  }
];

exports.getCsrfToken = (req, res) => {
  try {
    const csrfToken = req.csrfToken();

    res.json({
      csrfToken,
      cookieTokenName: 'XSRF-TOKEN',
    });
  } catch (error) {
    console.error('Error in CSRF token endpoint:', error);
    res.status(500).send('Server error');
  }
};