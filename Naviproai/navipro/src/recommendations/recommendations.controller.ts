import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RecommendationsService } from './recommendations.service';

interface AuthenticatedRequest {
  user: {
    userId: string;
    email: string;
  };
}

@Controller('recommendations')
@UseGuards(AuthGuard('jwt'))
export class RecommendationsController {
  constructor(
    private readonly recommendationsService: RecommendationsService,
  ) {}

  @Get('weekly-videos')
  async getWeeklyVideos(@Request() req: AuthenticatedRequest) {
    const userId = req.user.userId;
    return this.recommendationsService.getWeeklyVideos(userId);
  }
}
