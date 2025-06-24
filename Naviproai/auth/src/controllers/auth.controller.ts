import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.model';
import { Document } from 'mongoose';
import crypto from 'crypto'; // For generating tokens
// import { RequestWithAuth } from '../middleware/auth.middleware'; // Removed as this file might not exist in your setup
import { sendEmail } from '../utils/helper'; // Import the email helper
import { validatePassword } from '../utils/validation'; // Import password validator
import { IUser } from '../models/user.model';

const sendTokenResponse = (user: any, statusCode: number, res: Response) => {
  // Create token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET!, {
    expiresIn: '1d',
  });

  const cookieOptions = {
    // Set cookie to expire in 1 day (in milliseconds)
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000), 
    // httpOnly: true makes the cookie inaccessible to client-side JavaScript,
    // protecting against XSS attacks.
    httpOnly: true,
    // secure: true ensures the cookie is only sent over HTTPS.
    // This should be true in production.
    secure: process.env.NODE_ENV === 'production',
  };

  res
    .status(statusCode)
    .cookie('jwt', token, cookieOptions)
    .json({
      success: true,
      // You can optionally send back some non-sensitive user data
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
};

const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Validate password strength
    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }
    
    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 3600000 * 24); // Token valid for 24 hours

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ 
      email, 
      password: hashed, 
      name,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: emailVerificationExpires
    });
    
    // Send verification email
    const verificationLink = `${process.env.BASE_URL || 'https://6859c11d9ad995f11899aee7--guileless-sunburst-55bbb8.netlify.app/'}/auth/verify-email/${verificationToken}`;
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>Welcome to NaviProAI, ${name}!</h2>
        <p>Thanks for registering! Please verify your email address by clicking the button below:</p>
        <p style="text-align: center;">
          <a href="${verificationLink}"
             style="display: inline-block;
                    padding: 10px 20px;
                    margin: 10px 0;
                    font-size: 16px;
                    color: white;
                    background-color: #007bff;
                    text-decoration: none;
                    border-radius: 5px;">
            Verify Email Address
          </a>
        </p>
        <p>If the button above doesn't work, copy and paste the following link into your browser:</p>
        <p><a href="${verificationLink}">${verificationLink}</a></p>
        <p>This link will expire in 24 hours. If you did not request this, please ignore this email.</p>
      </div>
    `;
    await sendEmail({
      to: email,
      subject: 'Verify Your Email for NaviProAI',
      html: emailHtml,
    });

    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET!, { expiresIn: '1d' });
    // It's debatable whether to return a token before email verification.
    // For now, we will, but inform the user.
    res.json({ message: 'User registered. Please check your email to verify your account.', token });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
};

const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    // Optionally, check if email is verified during login
    // if (user && !user.isEmailVerified) {
    //   return res.status(401).json({ error: 'Please verify your email before logging in.' });
    // }
    if (!user || !user.password || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET!, { expiresIn: '1d' });
    res.json({ token });
    sendTokenResponse(user, 200, res);
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
    sendTokenResponse(req.user, 200, res);
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

    // Validate new password strength
    const passwordError = validatePassword(newPassword);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }
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

const verifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() }, // Check if token is not expired
    });

    if (!user) {
      // Redirect to a frontend page indicating failure or token expiry
      return res.status(400).redirect('/index.html?verification_error=invalid_or_expired_token');
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    // Redirect to a frontend page indicating success
    res.redirect('/index.html?verified=true');
  } catch (error) {
    console.error('Error verifying email:', error);
    // Redirect to a frontend page indicating a server error
    res.status(500).redirect('/index.html?verification_error=server_error');
  }
};

const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Please provide an email address.' });
    }

    const user = await User.findOne({ email });

    // To prevent email enumeration, always send a similar response
    // whether the user exists or not.
    if (!user || !user.password) { // Also check if user has a password (i.e., not Google-only user)
      console.log(`Password reset requested for non-existent or OAuth user: ${email}`);
      return res.status(200).json({ message: 'If your email is registered and has a password, you will receive a password reset link.' });
    }

    // 1. Generate the random reset token (this is the token sent to the user)
    const resetToken = crypto.randomBytes(32).toString('hex');

    // 2. Hash the token and set it on the user model (store the HASHED token in DB)
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    // 3. Set token expiration (e.g., 15 minutes)
    user.passwordResetExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save({ validateBeforeSave: false }); // Skip full validation if only updating these

    // 4. Create reset URL and send email
    //    The URL should point to your FRONTEND reset password page
    const resetURL = `${process.env.FRONTEND_URL || 'https://6859c11d9ad995f11899aee7--guileless-sunburst-55bbb8.netlify.app/'}/reset-password/${resetToken}`;

    const emailHtml = `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>NaviProAI Password Reset Request</h2>
        <p>You are receiving this email because you (or someone else) have requested to reset the password for your account.</p>
        <p>Please click the button below to reset your password. This link is valid for 15 minutes:</p>
        <p style="text-align: center;">
          <a href="${resetURL}"
             style="display: inline-block;
                    padding: 10px 20px;
                    margin: 10px 0;
                    font-size: 16px;
                    color: white;
                    background-color: #007bff;
                    text-decoration: none;
                    border-radius: 5px;">
            Reset Your Password
          </a>
        </p>
        <p>If the button above doesn't work, copy and paste the following link into your browser:</p>
        <p><a href="${resetURL}">${resetURL}</a></p>
        <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
      </div>
    `;

    const emailSent = await sendEmail({
      to: user.email as string, // email is guaranteed by findOne
      subject: 'Your NaviProAI Password Reset Token (Valid for 15 min)',
      html: emailHtml,
    });

    if (!emailSent) {
      // If email sending fails, we should ideally not leave the token in the DB,
      // or log this for manual intervention. For simplicity, we'll clear them.
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });
      return res.status(500).json({ error: 'Error sending password reset email. Please try again later.' });
    }

    res.status(200).json({ message: 'Password reset token sent to email.' });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    // Generic error to the client
    res.status(500).json({ error: 'An error occurred while processing your request.' });
  }
};

const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;
    const { password: newPassword } = req.body; // Renaming for clarity

    // Validate new password strength
    const passwordError = validatePassword(newPassword);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    // 1. Get user based on the token (hashed version) and expiry
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }, // Check if token is not expired
    });

    if (!user) {
      return res.status(400).json({ error: 'Token is invalid or has expired. Please request a new one.' });
    }

    // 2. If token is valid, set the new password
    user.password = await bcrypt.hash(newPassword, 12);
    user.passwordResetToken = undefined; // Clear the token
    user.passwordResetExpires = undefined; // Clear the expiry
    await user.save();

    // 3. Optionally, send a confirmation email
    const confirmationHtml = `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>NaviProAI Password Changed Successfully</h2>
        <p>Your password for NaviProAI has been successfully changed.</p>
        <p>If you did not make this change, please contact our support team immediately.</p>
      </div>
    `;
    await sendEmail({
      to: user.email as string,
      subject: 'Your NaviProAI Password Has Been Changed',
      html: confirmationHtml,
    });

    res.status(200).json({ message: 'Password has been reset successfully.' });

  } catch (error) {
    console.error('Reset Password Error:', error);
    res.status(500).json({ error: 'An error occurred while resetting your password.' });
  }
};
const logout = (req: Request, res: Response) => {
  res.cookie('jwt', '', {
    httpOnly: true,
    expires: new Date(0),
  });
  res.status(200).json({ message: 'Logged out successfully' });
};

export default {
  register,
  login,
  googleCallback,
  getUserProfile, // Assuming this was added
  changePassword,
  verifyEmail,
  forgotPassword,
  resetPassword,
  logout,
};
