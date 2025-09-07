import {
  Controller,
  Get,
  Req,
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
import type { Request } from 'express';
import { AuthService, LoginResult } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '../config/config.service';
import { User } from '../user/user.schema';

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

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @Redirect()
  async googleAuthCallback(@Req() req: Request & { user: User }) {
    const result = await this.authService.handleGoogleLogin(req.user);
    await this.aiService.handleUserLogin(result.user._id, result.access_token);

    const redirectUrl = new URL(result.redirectUrl);
    redirectUrl.searchParams.set('accessToken', result.access_token);
    redirectUrl.searchParams.set('userId', result.user._id.toString());

    return { url: redirectUrl.toString() };
  }

  @Get('verify-email')
  @Redirect()
  async verifyEmail(@Query('token') token: string) {
    const result = await this.authService.verifyEmail(token);
    return { url: result.redirectUrl };
  }
}