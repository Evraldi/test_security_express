const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function register({ email, password, name }) {
  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    return null;
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = await prisma.user.create({
    data: { email, password: hashedPassword, name },
  });
  return newUser;
}

async function login(email, password) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return { user: null, token: null };
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return { user: null, token: null };
  }

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_PASSPHRASE, { expiresIn: '1h' });
  return { user, token };
}

module.exports = {
  register,
  login,
};
