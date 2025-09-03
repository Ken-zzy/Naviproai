import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from './config/config.module';
import { ConfigService } from './config/config.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { EmailModule } from './email/email.module';
import { RoadmapModule } from './roadmap/roadmap.module';
import { AiModule } from './ai/ai.module';
import { ProgressModule } from './progress/progress.module';
import { RecommendationsModule } from './recommendations/recommendations.module';
import { StreakModule } from './streak/streak.module';
import { NotificationsModule } from './notifications/notifications.module';
import { PushNotificationsModule } from './push-notifications/push-notifications.module';

@Module({
  imports: [
    ConfigModule,
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        uri: configService.mongodbUri,
      }),
    }),
    UserModule,
    AuthModule,
    EmailModule,
    RoadmapModule,
    AiModule,
    ProgressModule,
    RecommendationsModule,
    StreakModule,
    NotificationsModule,
    PushNotificationsModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
