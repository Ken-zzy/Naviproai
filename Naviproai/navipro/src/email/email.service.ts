import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '../config/config.service';
import Mail from 'nodemailer/lib/mailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: Mail;

  constructor(private readonly configService: ConfigService) {
    const transportOptions = {
      host: this.configService.emailHost,
      port: this.configService.emailPort,
      secure: this.configService.emailSecure,
      auth: {
        user: this.configService.emailUser,
        pass: this.configService.emailPass,
      },
      connectionTimeout: 10000, // 10 seconds
    };

    this.logger.log('Initializing email transporter with options:');
    this.logger.log(`Host: ${transportOptions.host}`);
    this.logger.log(`Port: ${transportOptions.port}`);
    this.logger.log(`Secure: ${transportOptions.secure}`);
    this.logger.log(`User: ${transportOptions.auth.user}`);

    this.transporter = nodemailer.createTransport(transportOptions);
  }

  async sendMail(mailOptions: Mail.Options) {
    try {
      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      this.logger.error(
        `Failed to send email to ${mailOptions.to}`,
        error instanceof Error ? error.stack : String(error),
      );
    }
  }

  async sendVerificationLink(email: string, token: string) {
    const url = `${this.configService.backendUrl}/auth/verify-email?token=${token}`;

    await this.sendMail({
      from: this.configService.emailFrom,
      to: email,
      subject: 'Welcome to NaviPro.ai! Confirm Your Email',
      html: `<p>Please click the link below to verify your email address:</p><p><a href="${url}">Verify Email</a></p>`,
    });
  }
}
