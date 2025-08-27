import { Test, TestingModule } from '@nestjs/testing';
import { ProgressController } from './progress.controller';
import { ProgressService } from './progress.service';

describe('ProgressController', () => {
  let controller: ProgressController;
  let service: ProgressService;

  const mockProgressService = {
    getProgress: jest.fn().mockResolvedValue({
      totalTasks: 10,
      completedTasks: 5,
      percentage: 50,
    }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ProgressController],
      providers: [
        {
          provide: ProgressService,
          useValue: mockProgressService,
        },
      ],
    }).compile();

    controller = module.get<ProgressController>(ProgressController);
    service = module.get<ProgressService>(ProgressService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getProgress', () => {
    it('should call the progress service and return progress data', async () => {
      const mockReq = { user: { userId: 'user-123', email: 'test@test.com' } };
      const result = await controller.getProgress(mockReq as any);

      expect(service.getProgress).toHaveBeenCalledWith(mockReq.user.userId);
      expect(result).toEqual({
        totalTasks: 10,
        completedTasks: 5,
        percentage: 50,
      });
    });
  });
});
