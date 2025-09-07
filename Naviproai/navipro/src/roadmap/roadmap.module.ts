import { Module, forwardRef } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RoadmapController } from './roadmap.controller';
import { RoadmapService } from './roadmap.service';
import { Roadmap, RoadmapSchema } from './schemas/roadmap.schema';
import { StreakModule } from '../streak/streak.module';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Roadmap.name, schema: RoadmapSchema }]),
    forwardRef(() => StreakModule), // <-- This makes StreakService available for injection
    
    forwardRef(() => UserModule), // <-- For UserService in the controller
  ],
  controllers: [RoadmapController],
  providers: [RoadmapService],
  exports: [RoadmapService], // <-- Export for AiModule to use
})
export class RoadmapModule {}
