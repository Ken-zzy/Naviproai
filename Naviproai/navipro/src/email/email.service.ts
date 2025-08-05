import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '../config/config.service';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly transporter: nodemailer.Transporter;
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

  async sendVerificationLink(email: string, token: string) {
    const url = `${this.configService.frontendUrl}/auth/verify-email?token=${token}`;

    const mailOptions = {
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

    await this.transporter.sendMail(mailOptions);
    this.logger.log(`Verification email sent to ${email}`);
  }
}