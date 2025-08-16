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
      html: `
        <h1>Welcome to NaviPro!</h1>
        <p>Thank you for registering. Please click the link below to verify your email address:</p>
        <a href="${url}" target="_blank">Verify Your Email</a>
        <p>If you did not register for this account, you can safely ignore this email.</p>
      `,
    };

    await this.sendMail(mailOptions);
  }
}