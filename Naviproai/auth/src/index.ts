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
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));

// Serve static files from the dedicated 'public' directory.
// This is more secure and prevents exposing sensitive project files.
app.use(express.static(path.resolve(__dirname, '../../../public')));

app.use('/auth', authRoutes);

const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGO_URI!)
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error(err));
