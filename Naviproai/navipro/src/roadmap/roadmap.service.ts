import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Roadmap, Task, Week } from './schemas/roadmap.schema';
import { StreakService } from '../streak/streaks.service';

@Injectable()
export class RoadmapService {
  constructor(
    @InjectModel(Roadmap.name) private readonly roadmapModel: Model<Roadmap>,
    private readonly streakService: StreakService,
  ) {}

  async createOrUpdateRoadmap(userId: string, roadmapData: any): Promise<Roadmap> {
    // Assuming roadmapData is the object from the AI containing a "months" array
    return this.roadmapModel.findOneAndUpdate(
      { userId },
      { userId, months: roadmapData.months },
      { new: true, upsert: true }, // Create if it doesn't exist, otherwise update
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

    // Find the first uncompleted task
    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        for (const task of week.daily_tasks) {
          if (!task.completed) {
            return task;
          }
        }
      }
    }

    return null; // All tasks are completed
  }

  async completeTask(userId: string, taskId: string): Promise<Roadmap> {
    const roadmap = await this.roadmapModel.findOne({ userId }).exec();
    if (!roadmap) {
      throw new NotFoundException('Roadmap not found for this user.');
    }

    let taskFound = false;
    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        const task = week.daily_tasks.find((t) => t.task_id === taskId);
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

    // Update the user's streak
    await this.streakService.updateStreak(userId);

    return roadmap.save();
  }

  async getCurrentWeek(userId: string): Promise<Week | null> {
    const roadmap = await this.roadmapModel.findOne({ userId }).exec();
    if (!roadmap) {
      return null;
    }

    // Find the first week with at least one uncompleted task
    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        const hasUncompletedTask = week.daily_tasks.some(task => !task.completed);
        if (hasUncompletedTask) {
          return week;
        }
      }
    }

    return null; // All tasks are completed
  }
}