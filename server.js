const express = require('express');
const connectDB = require('./config/db');
require('dotenv').config();

const helmet = require('helmet');
const cors = require('cors');

const { rateLimiter } = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');

const logger = require('./utils/logger');


const app = express();

// Connect to database
connectDB();

// Security middleware
app.use(helmet());
app.use(cors({ origin: process.env.BASE_URL }));
app.use(rateLimiter);
app.use(express.json({ extended: false }));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
  });
});

// Error handler (must be last)
app.use(errorHandler);

const server = app.listen(process.env.PORT || 3000, () => {
  logger.info(`🚀 Server running on port ${process.env.PORT || 3000}`);
});

module.exports = app;
