const express = require('express');
const router = express.Router();
const { register, login, forgotPassword, resetPassword, showResetPasswordPage } = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.get('/reset-password', showResetPasswordPage);


module.exports = router;
