const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function getUserByEmail(email) {
  return prisma.user.findUnique({ where: { email } });
}

async function createUser(userData) {
  return prisma.user.create({ data: userData });
}

module.exports = {
  getUserByEmail,
  createUser,
};
