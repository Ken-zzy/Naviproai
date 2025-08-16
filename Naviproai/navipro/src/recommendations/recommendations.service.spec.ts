import { Test, TestingModule } from '@nestjs/testing';
import { RecommendationsService } from './recommendations.service';
import { ConfigService } from '../config/config.service';
import { RoadmapService } from '../roadmap/roadmap.service';

describe('RecommendationsService', () => {
  let service: RecommendationsService;
  let configService: ConfigService;
  let roadmapService: RoadmapService;

  const mockConfigService = {
    youtubeApiKey: 'test-key',
  };

  const mockRoadmapService = {
    getCurrentWeek: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RecommendationsService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: RoadmapService, useValue: mockRoadmapService },
      ],
    }).compile();

    service = module.get<RecommendationsService>(RecommendationsService);
    configService = module.get<ConfigService>(ConfigService);
    roadmapService = module.get<RoadmapService>(RoadmapService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
