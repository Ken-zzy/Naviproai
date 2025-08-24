import { Test, TestingModule } from '@nestjs/testing';
import { StreakController } from './streak.controller';
import { StreakService } from './streak.service';
import { UpdateStreakTypeDto } from './dto/update-streak-type.dto';
import { StreakType } from '../user/user.schema';

describe('StreakController', () => {
  let controller: StreakController;
  let service: StreakService;

  const mockStreakService = {
    getStreak: jest.fn().mockResolvedValue({ currentStreak: 5, longestStreak: 10, streakType: 'daily' }),
    setStreakType: jest.fn().mockImplementation((userId, streakType) => Promise.resolve({ streakType })),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [StreakController],
      providers: [
        {
          provide: StreakService,
          useValue: mockStreakService,
        },
      ],
    }).compile();

    controller = module.get<StreakController>(StreakController);
    service = module.get<StreakService>(StreakService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getStreak', () => {
    it('should call the service to get the streak for the authenticated user', async () => {
      const mockReq = { user: { id: 'user-123' } };
      await controller.getStreak(mockReq);
      expect(service.getStreak).toHaveBeenCalledWith(mockReq.user.id);
    });
  });

  describe('setStreakType', () => {
    it('should call the service to set the streak type for the authenticated user', async () => {
      const mockReq = { user: { id: 'user-123' } };
      const dto: UpdateStreakTypeDto = { streakType: StreakType.WEEKLY };
      await controller.setStreakType(mockReq, dto);
      expect(service.setStreakType).toHaveBeenCalledWith(mockReq.user.id, dto.streakType);
    });
  });
});
