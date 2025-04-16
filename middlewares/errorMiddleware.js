/**
 * Centralized error handling middleware
 * Handles different types of errors with appropriate status codes
 */
function errorHandler(err, req, res, next) {
  // Log error details (consider using a proper logging library in production)
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    console.error('Error details:', err);
  } else {
    // In production, log less verbose information
    console.error(`Error: ${err.name} - ${err.message}`);
  }

  // Handle specific error types
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      status: 'error',
      message: err.message,
      errors: err.errors
    });
  }

  if (err.name === 'UnauthorizedError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({
      status: 'error',
      message: 'Authentication failed'
    });
  }

  if (err.name === 'ForbiddenError') {
    return res.status(403).json({
      status: 'error',
      message: 'Access denied'
    });
  }

  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      status: 'error',
      message: 'Invalid CSRF token'
    });
  }

  // Default to 500 server error
  const statusCode = err.statusCode || 500;

  // Don't expose error details in production
  const responseBody = {
    status: 'error',
    message: isProduction ? 'An unexpected error occurred' : err.message
  };

  // Include stack trace in development
  if (!isProduction && err.stack) {
    responseBody.stack = err.stack;
  }

  res.status(statusCode).json(responseBody);
}

module.exports = errorHandler;
