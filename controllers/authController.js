const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

exports.forgotPassword = [
  body('email').isEmail().withMessage('Invalid email address'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(400).json({ msg: 'User does not exist' });
      }

      if (user.resetToken && user.resetTokenExpiry > Date.now()) {
        return res.status(400).json({ msg: 'A reset request is already pending' });
      }

      const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      user.resetToken = resetToken;
      user.resetTokenExpiry = new Date(Date.now() + 3600000);
      await user.save();

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset',
        text: `Click the link to reset your password: https://idk.com/api/auth/reset-password?token=${resetToken}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return res.status(500).send('Failed to send reset email');
        }
        res.json({ msg: 'Password reset email sent' });
      });
    } catch (err) {
      console.error('Error in forgotPassword:', err);
      res.status(500).send('Server Error');
    }
  }
];

exports.resetPassword = [
  body('token').not().isEmpty().withMessage('Token is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { token, newPassword } = req.body;

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (!decoded || !decoded.id) {
        return res.status(400).json({ msg: 'Invalid token' });
      }

      const user = await User.findByPk(decoded.id);
      if (!user) {
        return res.status(400).json({ msg: 'User not found' });
      }

      if (user.resetToken !== token || user.resetTokenExpiry < Date.now()) {
        return res.status(400).json({ msg: 'Invalid or expired token' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.resetToken = null;
      user.resetTokenExpiry = null;
      await user.save();

      res.json({ msg: 'Password has been reset' });
    } catch (err) {
      console.error('Error in resetPassword:', err);
      res.status(500).send('Server Error');
    }
  }
];

exports.register = [
  body('email').isEmail().withMessage('Invalid email address'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('username').not().isEmpty().withMessage('Username is required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, email } = req.body;

    try {
      const existingUser = await User.findOne({ where: { email } });
      if (existingUser) {
        return res.status(400).json({ msg: 'Email already in use' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = await User.create({ username, password: hashedPassword, email });
      res.json(newUser);
    } catch (err) {
      console.error('Server error in register:', err);
      res.status(500).send('Server Error');
    }
  }
];

exports.getCsrfToken = (req, res) => {
  try {
    const csrfToken = req.csrfToken();

    res.json({
      csrfToken,
      cookieTokenName: 'XSRF-TOKEN',
      message: "Use the CSRF token in the 'X-XSRF-TOKEN' header of your requests. Ensure it matches the token in the 'XSRF-TOKEN' cookie.",
    });
  } catch (error) {
    console.error('Error in CSRF token endpoint:', error);
    res.status(500).send('Server error');
  }
};

exports.login = [
  body('email').isEmail().withMessage('Invalid email address'),
  body('password').not().isEmpty().withMessage('Password is required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ where: { email } });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ msg: 'Invalid credentials' });
      }

      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } catch (err) {
      res.status(500).send('Server Error');
    }
  }
];

exports.showResetPasswordPage = (req, res) => {
  console.log('Rendering reset password page');
  res.send(`
    <form action="/api/auth/reset-password" method="POST">
      <input type="hidden" name="token" value="${req.query.token}" />
      <input type="password" name="newPassword" placeholder="New Password" required />
      <button type="submit">Reset Password</button>
    </form>
  `);
};
