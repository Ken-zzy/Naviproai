import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Nodemailer configuration
const emailHost = process.env.EMAIL_HOST;
const emailPort = process.env.EMAIL_PORT ? parseInt(process.env.EMAIL_PORT, 10) : 587;
const emailSecure = process.env.EMAIL_SECURE === 'true'; // true for 465, false for other ports like 587
const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASS;
const emailFrom = process.env.EMAIL_FROM; // e.g., '"Your App Name" <you@example.com>'

let transporter: nodemailer.Transporter | null = null;

if (emailHost && emailUser && emailPass && emailFrom) {
  transporter = nodemailer.createTransport({
    host: emailHost,
    port: emailPort,
    secure: emailSecure, 
    auth: {
      user: emailUser,
      pass: emailPass,
    },
  });
  console.log('Nodemailer email service initialized.');
} else {
  console.error('Nodemailer email service NOT initialized. Required EMAIL_HOST, EMAIL_USER, EMAIL_PASS, or EMAIL_FROM is missing.');
}

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string; // Optional plain text version
}

export const sendEmail = async (options: EmailOptions): Promise<boolean> => {
  if (!transporter) {
    console.error('Nodemailer transporter is not initialized. Email not sent.');
    return false;
  }

  const mailOptions = {
    from: emailFrom, // Sender address
    to: options.to,
    subject: options.subject,
    html: options.html,
    text: options.text || options.html.replace(/<[^>]*>?/gm, ''), // Basic text version from HTML
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Email sent successfully to ${options.to}`);
    return true;
  } catch (error) {
    console.error('Error sending email via Nodemailer:', error);
    // Depending on your error handling strategy, you might want to throw the error
    // throw error; // Option 1: re-throw the error
    return false; // Option 2: return a failure status
  }
};