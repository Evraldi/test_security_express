const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const LoginAttempt = sequelize.define('LoginAttempt', {
  email: {
    type: DataTypes.STRING,
    allowNull: false
  },
  attemptedAt: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  success: {
    type: DataTypes.BOOLEAN,
    allowNull: false
  }
}, {
  timestamps: false,
  tableName: 'login_attempts'
});

module.exports = LoginAttempt;
