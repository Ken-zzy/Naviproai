import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
  constructor(private nestConfig: NestConfigService) {}

  get port(): number {
    return this.nestConfig.get<number>('PORT', 3000);
  }

  get databaseUrl(): string {
    return this.nestConfig.get<string>('DATABASE_URL', '');
  }

  get jwtSecret(): string {
    return this.nestConfig.get<string>('JWT_SECRET', 'default-secret');
  }

  get jwtExpiresIn(): string {
    return this.nestConfig.get<string>('JWT_EXPIRES_IN', '60m');
  }

  get aiAgentUrl(): string {
    return this.nestConfig.get<string>('AI_AGENT_URL', '');
  }

  get aiAgentKey(): string {
    return this.nestConfig.get<string>('AI_AGENT_KEY', '');
  }

  get emailHost(): string {
    return this.nestConfig.get<string>('EMAIL_HOST', '');
  }

  get emailPort(): number {
    return this.nestConfig.get<number>('EMAIL_PORT', 587);
  }

  get emailSecure(): boolean {
    return this.nestConfig.get<boolean>('EMAIL_SECURE', false);
  }

  get emailUser(): string {
    return this.nestConfig.get<string>('EMAIL_USER', '');
  }

  get emailPass(): string {
    return this.nestConfig.get<string>('EMAIL_PASS', '');
  }

  get googleClientId(): string {
    return this.nestConfig.get<string>('GOOGLE_CLIENT_ID', '');
  }

  get googleClientSecret(): string {
    return this.nestConfig.get<string>('GOOGLE_CLIENT_SECRET', '');
  }

  get googleCallbackUrl(): string {
    return this.nestConfig.get<string>('GOOGLE_CALLBACK_URL', '');
  }

  get backendUrl(): string {
    return this.nestConfig.get<string>('BACKEND_URL', 'http://localhost:3000');
  }

  get emailFrom(): string {
    return this.nestConfig.get<string>('EMAIL_FROM', 'noreply@localhost');
  }

  get youtubeApiKey(): string | undefined {
    return this.nestConfig.get<string>('YOUTUBE_API_KEY');
  }

  get oneSignalAppId(): string | undefined {
    return this.nestConfig.get<string>('ONESIGNAL_APP_ID');
  }

  get oneSignalApiKey(): string | undefined {
    return this.nestConfig.get<string>('ONESIGNAL_API_KEY');
  }
}