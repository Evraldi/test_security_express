const jwt = require('jsonwebtoken');
const fs = require('fs');

// Get key for JWT verification
let verificationKey;
try {
  // Try to load public key for asymmetric verification
  verificationKey = process.env.PUBLIC_KEY_PATH ?
    fs.readFileSync(process.env.PUBLIC_KEY_PATH, 'utf8') :
    process.env.JWT_SECRET;
} catch (error) {
  console.error('Error loading public key:', error.message);
  // Fallback to JWT_SECRET if file can't be read
  verificationKey = process.env.JWT_SECRET;
}

/**
 * Authentication middleware that verifies JWT tokens
 * Supports both symmetric (HS256) and asymmetric (RS256) algorithms
 */
function authMiddleware(req, res, next) {
  // Get token from Authorization header or cookie
  const authHeader = req.header('Authorization');
  const token = authHeader?.startsWith('Bearer ') ?
    authHeader.substring(7) :
    req.cookies?.token;

  if (!token) {
    return res.status(401).json({
      message: 'Access denied. No token provided.'
    });
  }

  try {
    // Determine algorithm based on key type
    const algorithm = process.env.PUBLIC_KEY_PATH ? 'RS256' : 'HS256';

    const decoded = jwt.verify(token, verificationKey, {
      algorithms: [algorithm],
      clockTolerance: 30, // 30 seconds tolerance for clock skew
    });

    // Set user info on request object
    req.user = {
      id: decoded.sub || decoded.id,
      email: decoded.email,
    };

    next();
  } catch (error) {
    console.error('Token verification failed:', error.message);

    // Return appropriate status based on error type
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired.' });
    }

    res.status(403).json({ message: 'Invalid token.' });
  }
}

module.exports = authMiddleware;
