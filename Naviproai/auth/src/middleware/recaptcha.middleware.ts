import { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

export const verifyRecaptcha = async (req: Request, res: Response, next: NextFunction) => {
  const recaptchaToken = req.body['g-recaptcha-response']; // Or req.query, or req.headers, depending on how frontend sends it

  if (!RECAPTCHA_SECRET_KEY) {
    console.error('reCAPTCHA secret key is not configured. Skipping verification in development/testing.');
    // In a production environment, you should strictly fail if the key is missing:
    // return res.status(500).json({ error: 'CAPTCHA configuration error. Service unavailable.' });
    return next(); // For development, allow skipping if not configured to avoid blocking.
  }

  if (!recaptchaToken) {
    return res.status(400).json({ error: 'CAPTCHA token is missing. Please complete the CAPTCHA.' });
  }

  try {
    // Define a type for the expected reCAPTCHA verification response
    interface RecaptchaResponse {
      success: boolean;
      'error-codes'?: string[];
    }
    const response = await axios.post(
      RECAPTCHA_VERIFY_URL,
      `secret=${RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`, // Form-urlencoded data
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const recaptchaData = response.data as RecaptchaResponse; // Cast to the defined type

    if (recaptchaData.success) {
 next(); // CAPTCHA verified successfully
    } else {
 return res.status(400).json({ error: 'Failed CAPTCHA verification.', details: recaptchaData['error-codes'] });
    }

  } catch (error) {
    console.error('Error verifying reCAPTCHA:', error);
    return res.status(500).json({ error: 'An error occurred during CAPTCHA verification.' });
  }
};