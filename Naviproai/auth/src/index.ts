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

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize()); // Initialize passport but NO sessions

const allowedOrigins = [
    process.env.FRONTEND_URL // 
].filter((origin): origin is string => !!origin);

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

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
