import { Module } from '@nestjs/common';
import { ProgressController } from './progress.controller';
import { ProgressService } from './progress.service';
import { RoadmapModule } from '../roadmap/roadmap.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [RoadmapModule, AuthModule],
  controllers: [ProgressController],
  providers: [ProgressService],
})
export class ProgressModule {}
