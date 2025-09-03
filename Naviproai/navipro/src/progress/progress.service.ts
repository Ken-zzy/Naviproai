import { Injectable } from '@nestjs/common';
import { RoadmapService } from '../roadmap/roadmap.service';
import { Task } from '../roadmap/schemas/roadmap.schema';

@Injectable()
export class ProgressService {
  constructor(private readonly roadmapService: RoadmapService) {}

  async getProgress(userId: string) {
    const roadmap = await this.roadmapService.getRoadmapByUserId(userId);
    if (!roadmap) {
      return { totalTasks: 0, completedTasks: 0, percentage: 0 };
    }

    let totalTasks = 0;
    let completedTasks = 0;

    roadmap.months.forEach((month) => {
      month.weeks.forEach((week) => {
        totalTasks += week.daily_tasks.length;
        completedTasks += week.daily_tasks.filter(
          (task: Task) => task.completed,
        ).length;
      });
    });

    const percentage = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;

    return { totalTasks, completedTasks, percentage: Math.round(percentage) };
  }
}
