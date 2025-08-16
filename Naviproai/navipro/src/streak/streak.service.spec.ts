import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { StreakService } from './streaks.service';
import { User, UserDocument, StreakType } from '../user/user.schema';
import { NotFoundException } from '@nestjs/common';

describe('StreakService', () => {
  let service: StreakService;
  let userModel: Model<UserDocument>;

  const mockUserModel = {
    findById: jest.fn(),
    findByIdAndUpdate: jest.fn(),
    // .save() will be mocked on the user object itself
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        StreakService,
        {
          provide: getModelToken(User.name),
          useValue: mockUserModel,
        },
      ],
    }).compile();

    service = module.get<StreakService>(StreakService);
    userModel = module.get<Model<UserDocument>>(getModelToken(User.name));
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  describe('updateStreak', () => {
    it('should start a new streak at 1 if none exists', async () => {
      const mockUser = {
        currentStreak: 0,
        longestStreak: 0,
        lastStreakIncrement: null,
        save: jest.fn().mockResolvedValue(this),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      await service.updateStreak('userId');

      expect(mockUser.currentStreak).toBe(1);
      expect(mockUser.longestStreak).toBe(1);
      expect(mockUser.save).toHaveBeenCalled();
    });

    it('should increment a daily streak on the next day', async () => {
      jest.setSystemTime(new Date('2024-01-10T10:00:00Z'));
      const mockUser = {
        currentStreak: 1,
        longestStreak: 1,
        streakType: StreakType.DAILY,
        lastStreakIncrement: new Date('2024-01-09T10:00:00Z'),
        save: jest.fn(),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      await service.updateStreak('userId');
      
      expect(mockUser.currentStreak).toBe(2);
      expect(mockUser.save).toHaveBeenCalled();
    });

    it('should not increment a daily streak on the same day', async () => {
      jest.setSystemTime(new Date('2024-01-10T12:00:00Z'));
      const mockUser = {
        currentStreak: 1,
        longestStreak: 1,
        streakType: StreakType.DAILY,
        lastStreakIncrement: new Date('2024-01-10T10:00:00Z'),
        save: jest.fn(),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      await service.updateStreak('userId');

      expect(mockUser.currentStreak).toBe(1);
      expect(mockUser.save).not.toHaveBeenCalled();
    });

    it('should reset a daily streak if it is broken', async () => {
      jest.setSystemTime(new Date('2024-01-12T10:00:00Z')); // 2 days later
      const mockUser = {
        currentStreak: 5,
        longestStreak: 5,
        streakType: StreakType.DAILY,
        lastStreakIncrement: new Date('2024-01-10T10:00:00Z'),
        save: jest.fn(),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      await service.updateStreak('userId');

      expect(mockUser.currentStreak).toBe(1);
      expect(mockUser.save).toHaveBeenCalled();
    });

    it('should increment a weekly streak on the next week', async () => {
      jest.setSystemTime(new Date('2024-01-17T10:00:00Z')); // Next week
      const mockUser = {
        currentStreak: 2,
        longestStreak: 2,
        streakType: StreakType.WEEKLY,
        lastStreakIncrement: new Date('2024-01-10T10:00:00Z'),
        save: jest.fn(),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      await service.updateStreak('userId');

      expect(mockUser.currentStreak).toBe(3);
      expect(mockUser.save).toHaveBeenCalled();
    });

    it('should not increment a weekly streak in the same week', async () => {
      jest.setSystemTime(new Date('2024-01-12T10:00:00Z')); // Same week
      const mockUser = {
        currentStreak: 2,
        longestStreak: 2,
        streakType: StreakType.WEEKLY,
        lastStreakIncrement: new Date('2024-01-10T10:00:00Z'),
        save: jest.fn(),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      await service.updateStreak('userId');

      expect(mockUser.currentStreak).toBe(2);
      expect(mockUser.save).not.toHaveBeenCalled();
    });

    it('should throw NotFoundException if user does not exist', async () => {
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(null) });
      await expect(service.updateStreak('nonexistentUser')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getStreak', () => {
    it('should return the current streak data', async () => {
      const mockUser = {
        currentStreak: 5,
        longestStreak: 10,
        streakType: StreakType.DAILY,
        lastStreakIncrement: new Date(),
        save: jest.fn(),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      const streak = await service.getStreak('userId');

      expect(streak.currentStreak).toBe(5);
      expect(streak.longestStreak).toBe(10);
      expect(mockUser.save).not.toHaveBeenCalled();
    });

    it('should reset the streak to 0 if it is broken', async () => {
      jest.setSystemTime(new Date('2024-01-15T10:00:00Z'));
      const mockUser = {
        currentStreak: 5,
        longestStreak: 10,
        streakType: StreakType.DAILY,
        lastStreakIncrement: new Date('2024-01-10T10:00:00Z'), // 5 days ago
        save: jest.fn().mockResolvedValue(this),
      };
      mockUserModel.findById.mockReturnValue({ exec: () => Promise.resolve(mockUser) });

      const streak = await service.getStreak('userId');

      expect(mockUser.currentStreak).toBe(0);
      expect(mockUser.save).toHaveBeenCalled();
      expect(streak.currentStreak).toBe(0);
    });
  });

  describe('setStreakType', () => {
    it('should update the streak type and reset the streak', async () => {
      mockUserModel.findByIdAndUpdate.mockReturnValue({ exec: () => Promise.resolve({}) });
      await service.setStreakType('userId', StreakType.WEEKLY);
      expect(mockUserModel.findByIdAndUpdate).toHaveBeenCalledWith('userId', expect.any(Object), { new: true });
    });
  });
});
