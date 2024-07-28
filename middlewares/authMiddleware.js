const jwt = require('jsonwebtoken');
const fs = require('fs');

const publicKey = fs.readFileSync(process.env.PUBLIC_KEY_PATH, 'utf8');

function authMiddleware(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).send('Access denied. No token provided.');
  }

  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).send('Invalid token.');
  }
}

module.exports = authMiddleware;
