import { Injectable, NotFoundException } from '@nestjs/common';
import { RoadmapService } from '../roadmap/roadmap.service';

@Injectable()
export class ProgressService {
  constructor(private readonly roadmapService: RoadmapService) {}

  async getUserProgress(userId: string) {
    const roadmap = await this.roadmapService.getRoadmapByUserId(userId);
    if (!roadmap) {
      throw new NotFoundException('Roadmap not found for this user.');
    }

    let totalTasks = 0;
    let completedTasks = 0;

    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        totalTasks += week.daily_tasks.length;
        completedTasks += week.daily_tasks.filter(task => task.completed).length;
      }
    }

    const percentage = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;

    return {
      totalTasks,
      completedTasks,
      percentage: Math.round(percentage),
    };
  }
}