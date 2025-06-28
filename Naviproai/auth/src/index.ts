import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import path from 'path';
import './config/passport';
import authRoutes from './routes/auth.routes';
import cors from 'cors';
import { errorHandler } from './middleware/error.middleware';

dotenv.config(); 

const app = express();

 // Initialize passport but NO sessions

const allowedOrigins = [
    process.env.FRONTEND_URL,           // e.g., https://navipro.netlify.app
    'http://127.0.0.1:5500'             // local frontend
].filter((origin): origin is string => !!origin);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

app.use('/auth', authRoutes);

// 404 handler for unknown routes
app.use((req, res, next) => {
  res.status(404).send('Not found');
});

// Centralized error handler. This must be the last middleware.
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGO_URI!)
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error(err));
