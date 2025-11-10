import {
  Controller,
  Get,
  Req,
  Res,
  UseGuards,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  Query,
  Redirect,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request, Response } from 'express';
import { AuthService, LoginResult } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '../config/config.service';
import { User } from '../user/user.schema';

import { ResendVerificationDto } from './dto/resend-verification.dto';

import { AiService } from '../ai/ai.service';


@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly aiService: AiService,
  ) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto) {
    const result = await this.authService.register(registerDto);
    if (result.redirectUrl) {
      // This is a simplified example; in a real app, you might handle
      // the redirect differently (e.g., returning the URL to the client)
      return { url: result.redirectUrl };
    }
    return result;
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
  ): Promise<LoginResult & { redirectUrl: string }> {
    const user = await this.authService.validateUser(
      loginDto.email,
      loginDto.password,
    );
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const loginResult = this.authService.login(user as User & { _id: string });
    return {
      ...loginResult,
      redirectUrl: this.configService.frontendDashboardUrl,
    };
  }

  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  async resendVerification(@Body() resendVerificationDto: ResendVerificationDto) {
    return this.authService.resendVerificationLink(resendVerificationDto.email);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(
    @Req() req: Request & { user: User },
    @Res() res: Response,
  ) {
    const result = await this.authService.handleGoogleLogin(req.user);
    await this.aiService.handleUserLogin(result.user._id, result.access_token);

    res.cookie('jwt', result.access_token, {
      httpOnly: true,
      secure: this.configService.nodeEnv === 'production',
      sameSite: 'strict',
    });
    const redirectWithId = `${result.redirectUrl}?user_id = ${encodeURIComponent(result.user._id)}`;
    return res.redirect(redirectWithId);
    // res.redirect(result.redirectUrl);
  }

  @Get('verify-email')
  @Redirect()
  async verifyEmail(@Query('token') token: string) {
    const result = await this.authService.verifyEmail(token);
    return { url: result.redirectUrl };
  }
}