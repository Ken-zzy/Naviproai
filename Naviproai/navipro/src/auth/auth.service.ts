import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UserService } from '../user/user.service';
import { RegisterDto } from './dto/register.dto';
import { User, AuthProvider } from '../user/user.schema';
import { EmailService } from '../email/email.service';
import * as crypto from 'crypto';
import { ConfigService } from '../config/config.service';

export interface LoginResult {
  access_token: string;
}

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private userService: UserService,
    private emailService: EmailService,
    private configService: ConfigService,
  ) {}

  async validateUser(
    email: string,
    pass: string,
  ): Promise<Omit<User, 'password'> | null> {
    const user = await this.userService.findByEmail(email);
    if (user && user.password && (await bcrypt.compare(pass, user.password))) {
      if (!user.isVerified) {
        throw new UnauthorizedException(
          'Please verify your email before logging in.',
        );
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user.toObject();
      return result;
    }
    return null;
  }

  login(user: Omit<User, 'password'> & { _id: string }): LoginResult {
    // The 'sub' (subject) of a JWT is typically the user's unique ID.
    const payload = { email: user.email, sub: user._id.toString() };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async register(
    dto: RegisterDto,
  ): Promise<{ message: string; redirectUrl?: string }> {
    const existingUser = await this.userService.findByEmail(dto.email);

    if (existingUser) {
      // If user exists and has a password, it's a conflict.
      if (existingUser.password) {
        throw new ConflictException('Email already registered');
      }
      // If user exists from Google login, add password to their account.
      existingUser.password = await bcrypt.hash(dto.password, 10);
      existingUser.providers.push(AuthProvider.EMAIL);
      await this.userService.save(existingUser);
      const loginResult = this.login(
        existingUser.toObject() as User & { _id: string },
      );
      return {
        message: 'User successfully registered and logged in.',
        redirectUrl: `${this.configService.frontendUrl}`,
        ...loginResult,
      };
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    const user = await this.userService.create({
      email: dto.email,
      name: dto.name,
      password: hashedPassword,
      verificationToken: verificationToken,
      providers: [AuthProvider.EMAIL],
    });

    await this.emailService.sendVerificationLink(user.email, verificationToken);

    return {
      message:
        'Registration successful. Please check your email to verify your account.',
      redirectUrl: `${this.configService.frontendUrl}/verify-email`,
    };
  }

  async verifyEmail(token: string) {
    const user = await this.userService.findByVerificationToken(token);
    if (!user) {
      throw new NotFoundException('Invalid verification token.');
    }

    user.isVerified = true;
    user.verificationToken = null;
    await this.userService.save(user);

    return {
      message: 'Email verified successfully. You can now log in.',
      redirectUrl: `${this.configService.frontendUrl}/login`,
    };
  }
  async resendVerificationLink(email: string): Promise<{ message: string }> {
    const user = await this.userService.findByEmail(email);

    if (!user || !user.password) {
      // To prevent email enumeration, we send a generic success message
      // even if the user doesn't exist or signed up with Google.
      return {
        message:
          'If an account with that email exists and requires verification, a new link has been sent.',
      };
    }

    if (user.isVerified) {
      throw new ConflictException('This account has already been verified.');
    }

    // Generate a new token and update the user
    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.verificationToken = verificationToken;
    await this.userService.save(user);

    await this.emailService.sendVerificationLink(user.email, verificationToken);
    return { message: 'A new verification link has been sent to your email.' };
  }

  async handleGoogleLogin(
    profile: User,
  ): Promise<LoginResult & { redirectUrl: string }> {
    let user = await this.userService.findByEmail(profile.email);

    if (user) {
      // User exists, link Google ID if not already linked
      if (!user.googleId) {
        user.googleId = profile.googleId;
        if (!user.providers.includes(AuthProvider.GOOGLE)) {
          user.providers.push(AuthProvider.GOOGLE);
        }
        // If user signed up with Google, mark as verified
        user.isVerified = true;
        await this.userService.save(user);
      }
    } else {
      // New user via Google
      user = await this.userService.create({
        email: profile.email,
        name: profile.name,
        googleId: profile.googleId,
        isVerified: true, // Google accounts are considered verified
        providers: [AuthProvider.GOOGLE],
      });
    }

    const loginResult = this.login(user.toObject() as User & { _id: string });
    return {
      ...loginResult,
      redirectUrl: `${this.configService.frontendUrl}`,
    };
  }
}
