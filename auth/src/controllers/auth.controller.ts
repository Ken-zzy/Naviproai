import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.model';
import { Document } from 'mongoose';
// import { RequestWithAuth } from '../middleware/auth.middleware'; // Removed as this file might not exist in your setup
import { IUser } from '../models/user.model'; // Assuming this was added in a previous step

const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashed, name });
    
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET!, { expiresIn: '1d' });
    res.json({ message: 'User registered', token });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
};

const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password!))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET!, { expiresIn: '1d' });
    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Login failed' });
  }
};

const googleCallback = (req: Request, res: Response): void => {
  try {
    // req.user is populated by Passport's verify callback with the Mongoose user document.
    // The type IUser already extends Document, so Document<...> & IUser is redundant if IUser is correctly defined.
    // Assuming IUser is 'export interface IUser extends Document', then 'req.user as IUser' is fine.
    const user = req.user as IUser; 

    if (!user || !user._id || !user.email) {
      // This case should ideally be handled by Passport's done(err) if user is not found/created
      // or if essential user properties are missing.
      console.error('Google callback: User object or essential properties missing from req.user', req.user);
      // Redirect to the index.html served by this backend
      res.redirect(`/index.html?error=authentication_profile_error`);
      return;
    }

    const token = jwt.sign({ userId: user._id.toString(), email: user.email }, process.env.JWT_SECRET!, { expiresIn: '1d' });
    // Redirect to the index.html served by this backend with the token
    res.redirect(`/index.html?token=${token}`);
  } catch (error) {
    console.error('Error in googleCallback:', error);
    // Redirect to the index.html served by this backend with an error
    res.redirect(`/index.html?error=google_callback_processing_error`);
  }
};

// Assuming getUserProfile was added in a previous step
const getUserProfile = async (req: Request, res: Response) => { // Changed to use standard Request
  try {
    // req.user is populated by authenticateJWT middleware and typed by types/express/index.d.ts
    // It can be JwtPayload or the Mongoose User document. For JWT auth, it's JwtPayload.
    const jwtPayload = req.user as import('../../types/jwtPayload').JwtPayload;

    if (!jwtPayload || !jwtPayload.userId) {
      return res.status(401).json({ error: 'Not authorized, user data not found in token' });
    }
    const user = await User.findById(jwtPayload.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ id: user._id, name: user.name, email: user.email });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to get user profile' });
  }
};

const changePassword = async (req: Request, res: Response) => { // Changed to use standard Request
  try {
    const { currentPassword, newPassword } = req.body;
    // req.user is populated by authenticateJWT middleware
    const jwtPayload = req.user as import('../../types/jwtPayload').JwtPayload;
    if (!jwtPayload || !jwtPayload.userId) {
      return res.status(401).json({ error: 'Not authorized' });
    }

    const user = await User.findById(jwtPayload.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.password) {
      return res.status(400).json({ error: 'User registered with Google. Password cannot be changed here.' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect current password' });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
};

export default {
  register,
  login,
  googleCallback,
  getUserProfile, // Assuming this was added
  changePassword,
};
