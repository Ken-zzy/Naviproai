import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ProgressService } from './progress.service';

interface AuthenticatedRequest {
  user: {
    userId: string;
    email: string;
  };
}

@Controller('progress')
@UseGuards(AuthGuard('jwt'))
export class ProgressController {
  constructor(private readonly progressService: ProgressService) {}

  @Get()
  async getUserProgress(@Request() req: AuthenticatedRequest) {
    const userId = req.user.userId;
    return this.progressService.getUserProgress(userId);
  }
}