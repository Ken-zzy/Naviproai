import { Controller, Get, Post, Param, UseGuards, Request } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RoadmapService } from './roadmap.service';

@Controller('roadmap')
@UseGuards(AuthGuard('jwt'))
export class RoadmapController {
  constructor(private readonly roadmapService: RoadmapService) {}

  @Get('daily-task')
  async getDailyTask(@Request() req) {
    const userId = req.user.id;
    return this.roadmapService.getDailyTask(userId);
  }

  @Post('complete-task/:taskId')
  async completeTask(@Request() req, @Param('taskId') taskId: string) {
    const userId = req.user.id;
    return this.roadmapService.completeTask(userId, taskId);
  }
}
