import { Test, TestingModule } from '@nestjs/testing';
import { StreakController } from './streak.controller';

describe('StreakController', () => {
  let controller: StreakController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [StreakController],
    }).compile();

    controller = module.get<StreakController>(StreakController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
