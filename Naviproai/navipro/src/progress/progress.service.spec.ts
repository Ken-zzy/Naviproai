import { Test, TestingModule } from '@nestjs/testing';
import { ProgressService } from './progress.service';
import { RoadmapService } from '../roadmap/roadmap.service';

describe('ProgressService', () => {
  let service: ProgressService;
  let roadmapService: RoadmapService;

  const mockRoadmapService = {
    getRoadmapByUserId: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProgressService,
        {
          provide: RoadmapService,
          useValue: mockRoadmapService,
        },
      ],
    }).compile();

    service = module.get<ProgressService>(ProgressService);
    roadmapService = module.get<RoadmapService>(RoadmapService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
