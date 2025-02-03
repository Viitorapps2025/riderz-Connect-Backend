const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const authRouter = require('./routers/authRouter');
const postsRouter = require('./routers/postsRouter');
const tripRouter = require('./routers/tripRouter');
const contactRouter = require('./routers/contactRouter');

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
  message: "Too many requests from this IP, try again later.",
});
app.use('/api/', apiLimiter);

// Dynamic CORS Configuration
app.use(
  cors({
    origin: (origin, callback) => {
      console.log("Origin of request:", origin); // Log origin
      
      callback(null, true); // Allow all origins
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  })
);

// Middleware
app.use(helmet());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Database connected');
  })
  .catch((err) => {
    console.error('Database connection error:', err);
  });

// Routes
app.use('/api/auth', authRouter);
app.use('/api/posts', postsRouter);
app.use('/api/trip', tripRouter);
app.use('/api/contact', contactRouter);

// Root Route
app.get('/', (req, res) => {
  res.json({ message: 'Hello from the server' });
});

// Centralized Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
