import { Module } from '@nestjs/common';
import { RecommendationsController } from './recommendations.controller';
import { RecommendationsService } from './recommendations.service';
import { ConfigModule } from '../config/config.module';
import { RoadmapModule } from '../roadmap/roadmap.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [ConfigModule, RoadmapModule, AuthModule],
  controllers: [RecommendationsController],
  providers: [RecommendationsService],
})
export class RecommendationsModule {}
