import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
  constructor(private nestConfigService: NestConfigService) {}

  get jwtSecret(): string {
    return this.nestConfigService.get<string>('JWT_SECRET')!;
  }

  get jwtExpiresIn(): string {
    return this.nestConfigService.get<string>('JWT_EXPIRES_IN')!;
  }

  get googleClientId(): string {
    return this.nestConfigService.get<string>('GOOGLE_CLIENT_ID')!;
  }

  get googleClientSecret(): string {
    return this.nestConfigService.get<string>('GOOGLE_CLIENT_SECRET')!;
  }

  get googleCallbackUrl(): string {
    return this.nestConfigService.get<string>('GOOGLE_CALLBACK_URL')!;
  }

  get mongodbUri(): string {
    return this.nestConfigService.get<string>('MONGODB_URI')!;
  }

  get emailFrom(): string {
    return this.nestConfigService.get<string>('EMAIL_FROM')!;
  }

  get awsAccessKeyId(): string {
    return this.nestConfigService.get<string>('AWS_ACCESS_KEY_ID')!;
  }

  get awsSecretAccessKey(): string {
    return this.nestConfigService.get<string>('AWS_SECRET_ACCESS_KEY')!;
  }

  get awsRegion(): string {
    return this.nestConfigService.get<string>('AWS_REGION')!;
  }

  get port(): number {
    return this.nestConfigService.get<number>('PORT')!;
  }

  get nodeEnv(): string {
    return this.nestConfigService.get<string>('NODE_ENV')!;
  }

  get backendUrl(): string {
    return this.nestConfigService.get<string>('BACKEND_URL')!;
  }

  get emailHost(): string {
    return this.nestConfigService.get<string>('EMAIL_HOST')!;
  }

  get emailPort(): number {
    return this.nestConfigService.get<number>('EMAIL_PORT')!;
  }

  get emailSecure(): boolean {
    // The value from .env will be a string 'true' or 'false'
    return this.nestConfigService.get<string>('EMAIL_SECURE') === 'true';
  }

  get emailUser(): string {
    return this.nestConfigService.get<string>('EMAIL_USER')!;
  }

  get emailPass(): string {
    return this.nestConfigService.get<string>('EMAIL_PASS')!;
  }

  get aiAgentUrl(): string {
    return this.nestConfigService.get<string>('AI_AGENT_URL')!;
  }

  get aiAgentKey(): string {
    return this.nestConfigService.get<string>('AI_AGENT_KEY')!;
  }

  get oneSignalAppId(): string {
    return this.nestConfigService.get<string>('ONE_SIGNAL_APP_ID')!;
  }

  get oneSignalApiKey(): string {
    return this.nestConfigService.get<string>('ONE_SIGNAL_API_KEY')!;
  }

  get youtubeApiKey(): string {
    return this.nestConfigService.get<string>('YOUTUBE_API_KEY')!;
  }

  get frontendUrl(): string {
    return this.nestConfigService.get<string>('FRONTEND_URL')!;
  }
}
