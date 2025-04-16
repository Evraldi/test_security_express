const authService = require('../services/authService');

/**
 * User registration controller
 * Creates a new user account if validation passes
 */
async function register(req, res, next) {
  try {
    // Extract only the fields we need to prevent mass assignment
    const { email, password, name } = req.body;

    const newUser = await authService.register({ email, password, name });

    if (!newUser) {
      return res.status(409).json({
        status: 'error',
        message: 'User with this email already exists'
      });
    }

    // Return success with user data (password hash already removed in service)
    res.status(201).json({
      status: 'success',
      message: 'Registration successful',
      user: newUser
    });
  } catch (error) {
    // Log error but don't expose details to client
    if (process.env.NODE_ENV !== 'production') {
      console.error('Registration error:', error);
    }

    // Handle specific errors
    if (error.message === 'Password does not meet security requirements') {
      return res.status(400).json({
        status: 'error',
        message: 'Password does not meet security requirements'
      });
    }

    // Pass to error handler middleware
    next(error);
  }
}

/**
 * User login controller
 * Authenticates user and returns JWT token
 */
async function login(req, res, next) {
  try {
    const { email, password } = req.body;
    const { user, token } = await authService.login(email, password);

    if (!token) {
      // Use consistent response time to prevent timing attacks
      // The actual check is in the service layer
      return res.status(401).json({
        status: 'error',
        message: 'Invalid credentials'
      });
    }

    // Set JWT as HTTP-only cookie for better security
    const isProduction = process.env.NODE_ENV === 'production';
    res.cookie('token', token, {
      httpOnly: true, // Not accessible via JavaScript
      secure: isProduction, // HTTPS only in production
      sameSite: isProduction ? 'Strict' : 'Lax',
      maxAge: 3600000, // 1 hour
    });

    // Also return token in response for API clients
    res.status(200).json({
      status: 'success',
      message: 'Login successful',
      user,
      token
    });
  } catch (error) {
    if (process.env.NODE_ENV !== 'production') {
      console.error('Login error:', error);
    }
    next(error);
  }
}

/**
 * Logout controller
 * Clears the auth cookie
 */
async function logout(req, res) {
  res.clearCookie('token');
  res.status(200).json({
    status: 'success',
    message: 'Logout successful'
  });
}

module.exports = {
  register,
  login,
  logout
};
