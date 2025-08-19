import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
  constructor(private readonly nestConfig: NestConfigService) {}

  private getRequired<T>(key: string): T {
    const value = this.nestConfig.get<T>(key);
    if (value === undefined || value === null) {
      throw new Error(`Configuration error: Missing required environment variable "${key}"`);
    }
    return value;
  }

  get jwtSecret(): string {
    return this.getRequired('JWT_SECRET');
  }

  get jwtExpiresIn(): string {
    return this.getRequired('JWT_EXPIRES_IN');
  }

  get databaseUrl(): string {
    return this.getRequired('DATABASE_URL');
  }

  get port(): number {
    return this.nestConfig.get('PORT');
  }

  get frontendUrl(): string {
    return this.getRequired('FRONTEND_URL');
  }

  get backendUrl(): string {
    return this.getRequired('BACKEND_URL');
  }

  get emailHost(): string {
    return this.getRequired('EMAIL_HOST');
  }

  get emailPort(): number {
    return this.nestConfig.get('EMAIL_PORT');
  }

  get emailSecure(): boolean {
    return this.nestConfig.get('EMAIL_SECURE');
  }

  get emailUser(): string {
    return this.getRequired('EMAIL_USER');
  }

  get emailPass(): string {
    return this.getRequired('EMAIL_PASS');
  }

  get emailFrom(): string {
    return this.getRequired('EMAIL_FROM');
  }

  get aiAgentUrl(): string {
    return this.getRequired('AI_AGENT_URL');
  }

  get aiAgentKey(): string {
    return this.getRequired('AI_AGENT_KEY');
  }

  get googleClientId(): string {
    return this.getRequired('GOOGLE_CLIENT_ID');
  }

  get googleClientSecret(): string {
    return this.getRequired('GOOGLE_CLIENT_SECRET');
  }

  get googleCallbackUrl(): string {
    return this.getRequired('GOOGLE_CALLBACK_URL');
  }

  get youtubeApiKey(): string | undefined {
    return this.nestConfig.get('YOUTUBE_API_KEY');
  }

  get oneSignalAppId(): string | undefined {
    return this.nestConfig.get('ONESIGNAL_APP_ID');
  }

  get oneSignalApiKey(): string | undefined {
    return this.nestConfig.get('ONESIGNAL_API_KEY');
  }
}