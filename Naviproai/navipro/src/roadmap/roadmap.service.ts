import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Roadmap, RoadmapDocument, Month, Week, Task } from './schemas/roadmap.schema';
import { StreakService } from '../streak/streak.service';
import { CreateRoadmapDto } from './dto/create-roadmap.dto';

@Injectable()
export class RoadmapService {
  constructor(
    @InjectModel(Roadmap.name) private readonly roadmapModel: Model<RoadmapDocument>,
    private readonly streakService: StreakService,
  ) {}

  async create(createRoadmapDto: CreateRoadmapDto): Promise<RoadmapDocument> {
    const newRoadmap = new this.roadmapModel(createRoadmapDto);
    return newRoadmap.save();
  }

  async createOrUpdateRoadmap(userId: string, roadmapData: { months: Month[] }): Promise<RoadmapDocument> {
    return this.roadmapModel.findOneAndUpdate(
      { userId },
      { months: roadmapData.months },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    ).exec();
  }

  async getRoadmapByUserId(userId: string): Promise<RoadmapDocument | null> {
    return this.roadmapModel.findOne({ userId }).exec();
  }

  async getDailyTask(userId: string): Promise<Task | null> {
    const roadmap = await this.getRoadmapByUserId(userId);
    if (!roadmap) {
      return null;
    }
    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        const task = week.daily_tasks.find(t => !t.completed);
        if (task) {
          return task;
        }
      }
    }
    return null;
  }

  async completeTask(userId: string, taskId: string): Promise<RoadmapDocument> {
    const roadmap = await this.getRoadmapByUserId(userId);
    if (!roadmap) {
      throw new NotFoundException('Roadmap not found for this user.');
    }

    let taskFound = false;
    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        const task = week.daily_tasks.find(t => t.task_id === taskId);
        if (task) {
          if (!task.completed) {
            task.completed = true;
            task.completed_date = new Date();
            // Assuming updateStreak exists to increment the user's streak
            await this.streakService.updateStreak(userId);
          }
          taskFound = true;
          break;
        }
      }
      if (taskFound) break;
    }

    if (!taskFound) {
      throw new NotFoundException(`Task with ID "${taskId}" not found.`);
    }

    return roadmap.save();
  }

  async getCurrentWeek(userId: string): Promise<Week | null> {
    const roadmap = await this.getRoadmapByUserId(userId);
    if (!roadmap) {
      return null;
    }
    for (const month of roadmap.months) {
      for (const week of month.weeks) {
        if (week.daily_tasks.some(t => !t.completed)) {
          return week;
        }
      }
    }
    return null;
  }
}