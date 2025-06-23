import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';
import User from '../models/user.model';

dotenv.config();

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackURL: process.env.GOOGLE_CALLBACK_URL!,
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0].value;
    let userName = profile.displayName;

    if (!userName) {
      if (profile.name?.givenName && profile.name?.familyName) {
        userName = `${profile.name.givenName} ${profile.name.familyName}`;
      } else if (profile.name?.givenName) {
        userName = profile.name.givenName;
      } else if (email) {
        userName = email.split('@')[0]; // Fallback to email username part
      } else {
        // If no name can be derived and name is strictly required,
        // this might be an error condition or you might assign a generic name.
        // For now, let's proceed, but Mongoose validation for 'name' will catch it if it's still undefined.
        // Alternatively, return done(new Error("Could not determine user name from Google profile."));
      }
    }

    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      const existingUserWithEmail = email ? await User.findOne({ email: email }) : null;
      if (existingUserWithEmail) {
        // Link Google account to existing user
        existingUserWithEmail.googleId = profile.id;
        // If the existing user doesn't have a name, and Google profile has one, update it.
        if (!existingUserWithEmail.name && userName) existingUserWithEmail.name = userName;
        user = await existingUserWithEmail.save();
      } else {
        user = await User.create({ googleId: profile.id, name: userName, email });
      }
    }
    done(null, user);
  } catch (error) {
    done(error, undefined);
  }
}));
