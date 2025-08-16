import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RoadmapController } from './roadmap.controller';
import { RoadmapService } from './roadmap.service';
import { Roadmap, RoadmapSchema } from './schemas/roadmap.schema';
import { StreakModule } from '../streak/streak.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Roadmap.name, schema: RoadmapSchema }]),
    StreakModule,
    AuthModule, // For protecting routes
  ],
  controllers: [RoadmapController],
  providers: [RoadmapService],
  exports: [RoadmapService], // Export so other modules like AiModule can use it
})
export class RoadmapModule {}
