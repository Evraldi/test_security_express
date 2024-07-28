// config/env/production.js

module.exports = {
  db: {
    url: process.env.DATABASE_URL,
  },
  jwtSecret: process.env.JWT_SECRET,
};
