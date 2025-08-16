import { Test, TestingModule } from '@nestjs/testing';
import { RoadmapService } from './roadmap.service';
import { getModelToken } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Roadmap, Task } from './schemas/roadmap.schema';
import { StreakService } from '../streak/streaks.service';
import { NotFoundException } from '@nestjs/common';

describe('RoadmapService', () => {
  let service: RoadmapService;
  let roadmapModel: Model<Roadmap>;
  let streakService: StreakService;

  const mockRoadmapModel = {
    findOneAndUpdate: jest.fn(),
    findOne: jest.fn(),
  };

  const mockStreakService = {
    updateStreak: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RoadmapService,
        {
          provide: getModelToken(Roadmap.name),
          useValue: mockRoadmapModel,
        },
        {
          provide: StreakService,
          useValue: mockStreakService,
        },
      ],
    }).compile();

    service = module.get<RoadmapService>(RoadmapService);
    roadmapModel = module.get<Model<Roadmap>>(getModelToken(Roadmap.name));
    streakService = module.get<StreakService>(StreakService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('getDailyTask', () => {
    it('should return the first uncompleted task', async () => {
      const mockRoadmap = {
        months: [{
          weeks: [{
            daily_tasks: [
              { task_id: '1', completed: true },
              { task_id: '2', completed: false },
            ],
          }],
        }],
      };
      mockRoadmapModel.findOne.mockReturnValue({ exec: () => Promise.resolve(mockRoadmap) });

      const task = await service.getDailyTask('userId');
      expect(task).toEqual({ task_id: '2', completed: false });
    });

    it('should return null if all tasks are completed', async () => {
      const mockRoadmap = {
        months: [{
          weeks: [{
            daily_tasks: [{ task_id: '1', completed: true }],
          }],
        }],
      };
      mockRoadmapModel.findOne.mockReturnValue({ exec: () => Promise.resolve(mockRoadmap) });

      const task = await service.getDailyTask('userId');
      expect(task).toBeNull();
    });
  });

  describe('completeTask', () => {
    it('should mark a task as complete and update the streak', async () => {
      const mockTask: Partial<Task> = { task_id: 'task-to-complete', completed: false };
      const mockRoadmap = {
        months: [{
          weeks: [{
            daily_tasks: [mockTask],
          }],
        }],
        save: jest.fn().mockResolvedValue(true),
      };
      mockRoadmapModel.findOne.mockReturnValue({ exec: () => Promise.resolve(mockRoadmap) });

      await service.completeTask('userId', 'task-to-complete');

      expect(mockTask.completed).toBe(true);
      expect(mockTask.completed_date).toBeInstanceOf(Date);
      expect(streakService.updateStreak).toHaveBeenCalledWith('userId');
      expect(mockRoadmap.save).toHaveBeenCalled();
    });

    it('should throw NotFoundException if task does not exist', async () => {
      const mockRoadmap = { months: [] };
      mockRoadmapModel.findOne.mockReturnValue({ exec: () => Promise.resolve(mockRoadmap) });

      await expect(service.completeTask('userId', 'nonexistent-task')).rejects.toThrow(NotFoundException);
    });
  });
});
