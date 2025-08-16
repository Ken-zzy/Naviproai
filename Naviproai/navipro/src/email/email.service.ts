import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';
import Mail from 'nodemailer/lib/mailer';

@Injectable()
export class EmailService {
  private readonly transporter: Transporter;
  private readonly logger = new Logger(EmailService.name);

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.emailHost,
      port: this.configService.emailPort,
      secure: this.configService.emailSecure, // true for 465, false for other ports
      auth: {
        user: this.configService.emailUser,
        pass: this.configService.emailPass,
      },
    });
  }

  async sendMail(mailOptions: Mail.Options): Promise<void> {
    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email sent successfully to ${mailOptions.to}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${mailOptions.to}`, error.stack);
      // Depending on the application's needs, you might want to re-throw the error
      // or handle it gracefully.
      throw error;
    }
  }

  async sendVerificationLink(email: string, token: string): Promise<void> {
    const url = `${this.configService.backendUrl}/auth/verify-email?token=${token}`;

    const mailOptions: Mail.Options = {
      from: this.configService.emailFrom,
      to: email,
      subject: 'Welcome to NaviPro! Please Verify Your Email',
      html: `<!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { padding: 20px; }
              .button { background-color: #007bff; color: white !important; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; }
              a { color: #007bff; }
          </style>
      </head>
      <body>
          <div class="container">
              <h1>Welcome to NaviPro!</h1>
              <p>Thank you for registering. Please click the button below to verify your email address:</p>
              <p><a href="${url}" target="_blank" class="button">Verify Your Email</a></p>
              <p>If you did not register for this account, you can safely ignore this email.</p>
          </div>
      </body>

      `,
    };

    await this.sendMail(mailOptions);
  }
}