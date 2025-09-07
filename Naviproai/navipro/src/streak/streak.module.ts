import { Module, forwardRef } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { StreakService } from './streak.service';
import { StreakController } from './streak.controller';
import { User, UserSchema } from '../user/user.schema';
import { AuthModule } from '../auth/auth.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    
    NotificationsModule, // Import to use NotificationsService
  ],
  controllers: [StreakController],
  providers: [StreakService],
  exports: [StreakService], // Export for other modules that depend on it
})
export class StreakModule {}
