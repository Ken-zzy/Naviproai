import { Module } from '@nestjs/common';
import { ProgressService } from './progress.service';
import { ProgressController } from './progress.controller';
import { RoadmapModule } from '../roadmap/roadmap.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    RoadmapModule, // Provides RoadmapService for progress tracking
    AuthModule,    // Provides AuthGuard for controller
  ],
  controllers: [ProgressController],
  providers: [ProgressService],
})
export class ProgressModule {}