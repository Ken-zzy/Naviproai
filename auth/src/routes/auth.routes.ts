import express from 'express';
import passport from 'passport';
import { protect } from '../middleware/authMiddleware'; // Assuming this was added
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

export default router;
