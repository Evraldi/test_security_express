const express = require('express');
const { connectDB, sequelize } = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const articleRoutes = require('./routes/articles');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

connectDB();

sequelize.sync()
  .then(() => console.log('Database synced...'))
  .catch(err => console.error('Error syncing database:', err));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api/articles', articleRoutes);
app.use('/api/auth', authRoutes);

app.use((err, req, res, next) => {
  console.error('Error occurred:', err.stack);
  res.status(500).send('Something broke!');
});

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT} at ${new Date().toISOString()}`);
});
