import { Router } from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { authenticateJWT } from '../middleware/authMiddleware';
import express from 'express';


dotenv.config();

const router = express.Router();

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const user = req.user as any;
  
  const token = jwt.sign(
    { id: user._id, email: user.email, name: user.name },
    process.env.JWT_SECRET!,
    { expiresIn: '1d' }
  );

  // You can send token directly or redirect with token in query
  // For example, redirect to frontend with token:
  res.redirect(`${process.env.CLIENT_URL}?token=${token}`);
});
router.get('/profile', authenticateJWT, (req: express.Request, res: express.Response, next: express.NextFunction) => {
  res.json({ user: (req as any).user });
});

export default router;