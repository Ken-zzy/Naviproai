import {
  Controller,
  Get,
  Post,
  Param,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RoadmapService } from './roadmap.service';

interface AuthenticatedRequest {
  user: {
    userId: string;
    email: string;
  };
}

@Controller('roadmap')
@UseGuards(AuthGuard('jwt'))
export class RoadmapController {
  constructor(private readonly roadmapService: RoadmapService) {}

  @Get('daily-task')
  async getDailyTask(@Request() req: AuthenticatedRequest) {
    const userId = req.user.userId;
    return this.roadmapService.getDailyTask(userId);
  }

  @Post('complete-task/:taskId')
  async completeTask(
    @Request() req: AuthenticatedRequest,
    @Param('taskId') taskId: string,
  ) {
    const userId = req.user.userId;
    return this.roadmapService.completeTask(userId, taskId);
  }
}
