import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import path from 'path';
import './config/passport';
import authRoutes from './routes/auth.routes';
import cors from 'cors';

dotenv.config(); 

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize()); // Initialize passport but NO sessions

const allowedOrigins = [
    'http://localhost:5173', // Your main frontend
    process.env.FRONTEND_URL // For local testing (http://localhost:3000)
].filter((origin): origin is string => typeof origin === 'string');

app.use(cors({ origin: allowedOrigins, credentials: true }));

// Serve the frontend test page and other static assets from the 'frontend' directory.
app.use(express.static(path.resolve(__dirname, '../../../frontend')));

app.use('/auth', authRoutes);

const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGO_URI!)
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error(err));
