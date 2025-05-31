import express from 'express';
import passport from 'passport';
import { authenticateJWT } from '../middleware/authMiddleware';
import authController from '../controllers/auth.controller';

const router = express.Router();

// Local authentication routes
router.post('/register', authController.register as express.RequestHandler);
router.post('/login', authController.login as express.RequestHandler);

// Google OAuth routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get(
  '/google/callback',
  passport.authenticate('google', { 
    session: false, 
    failureRedirect: '/index.html?error=google_authentication_failed' // Redirect to index.html with error
  }),
  // authController.googleCallback is responsible for handling the user profile from Google,
  // generating a JWT, and then redirecting to: /index.html?token=YOUR_GENERATED_TOKEN
  authController.googleCallback
);

// Protected routes
router.get('/profile', authenticateJWT, authController.getUserProfile as express.RequestHandler);
router.post('/change-password', authenticateJWT, authController.changePassword as express.RequestHandler);


export default router;
