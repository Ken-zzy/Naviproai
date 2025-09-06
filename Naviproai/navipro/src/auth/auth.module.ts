import { Global, Module, forwardRef } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import { UserModule } from '../user/user.module';
import { ConfigModule } from '../config/config.module';
import { ConfigService } from '../config/config.service';
import { EmailModule } from '../email/email.module';
import { GoogleStrategy } from './google.strategy';
import { AiModule } from '../ai/ai.module';

@Global()
@Module({
  imports: [
    PassportModule,
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.jwtSecret,
        signOptions: { expiresIn: configService.jwtExpiresIn },
      }),
    }),
    forwardRef(() => UserModule),
    EmailModule,
    AiModule,
  ],
  providers: [AuthService, JwtStrategy, GoogleStrategy],
  controllers: [AuthController],
  exports: [AuthService, JwtModule, PassportModule],
})
export class AuthModule {}
