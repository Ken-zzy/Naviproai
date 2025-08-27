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
}