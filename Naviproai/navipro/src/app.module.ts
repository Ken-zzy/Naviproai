// app.module.ts
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { AiModule } from './ai/ai.module';
import { RoadmapModule } from './roadmap/roadmap.module';
import { ProgressModule } from './progress/progress.module';
import { StreakModule } from './streak/streak.module';
import { NotificationsModule } from './notifications/notifications.module';
import { RecommendationsModule } from './recommendations/recommendations.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from './config/config.module';
import { ConfigService } from './config/config.service';
import { EmailModule } from './email/email.module';
import { ThrottlerGuard, ThrottlerModule } from 'nestjs-throttler';
import { APP_GUARD } from '@nestjs/core';
import { PushNotificationsModule } from './push-notifications/push-notifications.module';

@Module({
  imports: [
    ConfigModule,
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.databaseUrl,
      }),
      inject: [ConfigService],
    }),
    ThrottlerModule.forRoot([{
      ttl: 60000, // 1 minute in milliseconds
      limit: 20,  // 20 requests per IP per minute
    }]),
    AuthModule,
    UserModule,
    AiModule,
    RoadmapModule,
    ProgressModule,
    StreakModule,
    NotificationsModule,
    RecommendationsModule,
    PushNotificationsModule,
    EmailModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}