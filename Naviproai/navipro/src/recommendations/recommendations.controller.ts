import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RecommendationsService } from './recommendations.service';

@Controller('week-videos')
@UseGuards(AuthGuard('jwt'))
export class RecommendationsController {
  constructor(
    private readonly recommendationsService: RecommendationsService,
  ) {}

  @Get()
  async getWeeklyVideos(@Request() req) {
    const userId = req.user.id;
    return this.recommendationsService.getWeeklyVideos(userId);
  }
}
