import { Test, TestingModule } from '@nestjs/testing';
import { RoadmapController } from './roadmap.controller';
import { RoadmapService } from './roadmap.service';

describe('RoadmapController', () => {
  let controller: RoadmapController;
  let service: RoadmapService;

  const mockRoadmapService = {
    getDailyTask: jest.fn(),
    completeTask: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [RoadmapController],
      providers: [
        {
          provide: RoadmapService,
          useValue: mockRoadmapService,
        },
      ],
    }).compile();

    controller = module.get<RoadmapController>(RoadmapController);
    service = module.get<RoadmapService>(RoadmapService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getDailyTask', () => {
    it('should call the service to get the daily task for the authenticated user', async () => {
      const mockReq = { user: { userId: 'user-123', email: 'test@test.com' } };
      await controller.getDailyTask(mockReq);
      expect(service.getDailyTask).toHaveBeenCalledWith(mockReq.user.userId);
    });
  });

  describe('completeTask', () => {
    it('should call the service to complete a task for the authenticated user', async () => {
      const mockReq = { user: { userId: 'user-123', email: 'test@test.com' } };
      await controller.completeTask(mockReq, 'task-id-123');
      expect(service.completeTask).toHaveBeenCalledWith(
        mockReq.user.userId,
        'task-id-123',
      );
    });
  });
});
