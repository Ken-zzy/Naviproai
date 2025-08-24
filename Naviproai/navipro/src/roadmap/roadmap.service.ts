import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Roadmap, Task, Week } from './schemas/roadmap.schema';
import { StreakService } from '../streak/streak.service';

@Injectable()
export class RoadmapService {
  constructor(
    @InjectModel(Roadmap.name) private readonly roadmapModel: Model<Roadmap>,
    private readonly streakService: StreakService,
  ) {}

  async createOrUpdateRoadmap(userId: string, roadmapData: any): Promise<Roadmap> {
    return this.roadmapModel.findOneAndUpdate(
      { userId },
      { userId, months: roadmapData.months },
      { new: true, upsert: true },
    ).exec();
  }

  async getRoadmapByUserId(userId: string): Promise<Roadmap | null> {
    return this.roadmapModel.findOne({ userId }).exec();
  }

  async getDailyTask(userId: string): Promise<Task | null> {
    const roadmap = await this.roadmapModel.findOne({ userId }).exec();
    if (!roadmap) {
      throw new NotFoundException('Roadmap not found for this user.');
    }

    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        for (const task of week.daily_tasks) {
          if (!task.completed) {
            return task;
          }
        }
      }
    }
    return null;
  }

  async completeTask(userId: string, taskId: string): Promise<Roadmap> {
    const roadmap = await this.roadmapModel.findOne({ userId }).exec();
    if (!roadmap) {
      throw new NotFoundException('Roadmap not found for this user.');
    }

    let taskFound = false;
    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        const task = week.daily_tasks.find((t: Task) => t.task_id === taskId);
        if (task && !task.completed) {
          task.completed = true;
          task.completed_date = new Date();
          taskFound = true;
          break;
        }
      }
      if (taskFound) break;
    }

    if (!taskFound) {
      throw new NotFoundException(`Task with ID ${taskId} not found or already completed.`);
    }

    await this.streakService.updateStreak(userId);
    return roadmap.save();
  }

  async getCurrentWeek(userId: string): Promise<Week | null> {
    const roadmap = await this.roadmapModel.findOne({ userId }).exec();
    if (!roadmap) {
      return null;
    }

    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        const hasUncompletedTask = week.daily_tasks.some((task: Task) => !task.completed);
        if (hasUncompletedTask) {
          return week;
        }
      }
    }
    return null;
  }
}