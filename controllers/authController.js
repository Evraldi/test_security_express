const authService = require('../services/authService');

async function register(req, res, next) {
  try {
    const newUser = await authService.register(req.body);
    if (!newUser) {
      return res.status(409).json({ message: 'User already exists' });
    }
    res.status(201).json({ user: newUser });
  } catch (error) {
    console.error('Registration error:', error);
    next(error);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const { user, token } = await authService.login(email, password);
    if (!token) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    res.status(200).json({ user, token });
  } catch (error) {
    console.error('Login error:', error);
    next(error);
  }
}

module.exports = {
  register,
  login,
};
