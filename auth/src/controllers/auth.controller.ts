import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.model';

export const register = async (req: Request, res: Response) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 12);
  const user = await User.create({ email, password: hashed, name });
  res.json({ message: 'User registered' });
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password!))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET!, { expiresIn: '1d' });
  res.json({ token });
};

export const googleCallback = (req: Request, res: Response) => {
  const token = jwt.sign({ userId: (req.user as any)._id }, process.env.JWT_SECRET!, { expiresIn: '1d' });
  res.redirect(`http://localhost:3000?token=${token}`);
};
