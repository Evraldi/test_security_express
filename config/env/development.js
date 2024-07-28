// config/env/development.js

module.exports = {
  db: {
    url: process.env.DATABASE_URL,
  },
  jwtSecret: process.env.JWT_SECRET,
};
