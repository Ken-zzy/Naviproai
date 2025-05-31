import express from 'express';
import passport from 'passport';
import { login, register, googleCallback } from '../controllers/auth.controller';

const router = express.Router();

router.post('/register', register);
router.post('/login', login as express.RequestHandler);
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { session: false }), googleCallback);

export default router;
