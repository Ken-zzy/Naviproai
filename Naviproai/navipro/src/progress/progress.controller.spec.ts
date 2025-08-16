import { Test, TestingModule } from '@nestjs/testing';
import { ProgressController } from './progress.controller';
import { ProgressService } from './progress.service';

describe('ProgressController', () => {
  let controller: ProgressController;
  let service: ProgressService;

  const mockProgressService = {
    getUserProgress: jest.fn().mockResolvedValue({
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

  describe('getUserProgress', () => {
    it('should call the progress service and return progress data', async () => {
      const mockReq = { user: { id: 'user-123' } };
      const result = await controller.getUserProgress(mockReq);

      expect(service.getUserProgress).toHaveBeenCalledWith(mockReq.user.id);
      expect(result).toEqual({
        totalTasks: 10,
        completedTasks: 5,
        percentage: 50,
      });
    });
  });
});
