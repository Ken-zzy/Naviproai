import { Test, TestingModule } from '@nestjs/testing';
import { StreakController } from './streak.controller';
import { StreakService } from './streak.service';
import { UpdateStreakTypeDto } from './dto/update-streak-type.dto';
import { StreakType } from '../user/user.schema';

describe('StreakController', () => {
  let controller: StreakController;
  let service: StreakService;

  const mockStreakService = {
    getStreak: jest.fn(),
    setStreakType: jest.fn(),
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
    it('should call the service to get a streak', async () => {
      const mockReq = { user: { sub: 'user-id-123' } };
      await controller.getStreak(mockReq as any);
      expect(service.getStreak).toHaveBeenCalledWith(mockReq.user.sub);
    });
  });

  describe('setStreakType', () => {
    it('should call the service to set the streak type', async () => {
      const mockReq = { user: { sub: 'user-id-123' } };
      const dto: UpdateStreakTypeDto = { streakType: StreakType.WEEKLY };
      await controller.setStreakType(mockReq as any, dto);
      expect(service.setStreakType).toHaveBeenCalledWith(
        mockReq.user.sub,
        dto.streakType,
      );
    });
  });
});
