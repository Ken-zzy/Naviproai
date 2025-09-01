import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { AiService } from './ai.service';
import { ConfigService } from '../config/config.service';
import { InternalServerErrorException } from '@nestjs/common';
import { RoadmapService } from '../roadmap/roadmap.service';
import { UserService } from '../user/user.service';
import { ChatHistory } from './schemas/chat-history.schema';
import got from 'got';

// Mock the 'got' module and its extend method
jest.mock('got', () => {
  const mockExtendedInstance = {
    get: jest.fn(),
    post: jest.fn(),
    patch: jest.fn(),
  };

  return {
    __esModule: true,
    default: {
      extend: jest.fn().mockReturnValue(mockExtendedInstance),
    },
  };
});

const mockedGot = got as jest.Mocked<typeof got>;

describe('AiService', () => {
  let service: AiService;
  let mockExtendedGot: any;

  const mockConfigService = {
    aiAgentUrl: 'http://fake-url.com',
    aiAgentKey: 'fake-key',
  };
  const mockRoadmapService = {
    createOrUpdateRoadmap: jest
      .fn()
      .mockImplementation((userId, data) => Promise.resolve({ userId, ...data })),
    getRoadmapByUserId: jest.fn().mockResolvedValue({ months: [] }),
  };
  const mockUserService = {
    findById: jest.fn().mockResolvedValue({ name: 'Test User' }),
  };
  const mockChatHistoryModel = {
    findOne: jest.fn().mockResolvedValue(null),
    findOneAndUpdate: jest.fn().mockReturnValue({
      exec: jest.fn().mockResolvedValue(true),
    }),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    // Get the mock extended instance
    mockExtendedGot = (got.extend as jest.Mock).mock.results[0].value;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AiService,
        { provide: ConfigService, useValue: mockConfigService },
        { provide: RoadmapService, useValue: mockRoadmapService },
        { provide: UserService, useValue: mockUserService },
        { provide: getModelToken(ChatHistory.name), useValue: mockChatHistoryModel },
      ],
    }).compile();

    service = module.get<AiService>(AiService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateRoadmap', () => {
    const userId = 'user-123';
    const dto = { targetRole: 'dev', currentLevel: 'beginner' };

    it('should call got.post with correct parameters and return data', async () => {
      const mockResponse = { roadmap: 'This is the roadmap' };
      const mockJsonResponse = jest.fn().mockResolvedValue(mockResponse);
      
      // Mock the extended instance's post method
      mockExtendedGot.post.mockReturnValue({
        json: mockJsonResponse,
      } as any);

      const result = await service.generateRoadmap(userId, dto);

      expect(mockExtendedGot.post).toHaveBeenCalledWith(
        'http://fake-url.com/api/generate_roadmap',
        {
          json: { targetRole: 'dev', currentLevel: 'beginner' },
        }
      );
      expect(mockJsonResponse).toHaveBeenCalled();
      expect(mockRoadmapService.createOrUpdateRoadmap).toHaveBeenCalledWith(userId, mockResponse);
      expect(result).toEqual({ userId, ...mockResponse });
    });

    it('should throw an InternalServerErrorException on failure', async () => {
      mockExtendedGot.post.mockRejectedValue(new Error('Network error'));
      
      await expect(service.generateRoadmap(userId, dto)).rejects.toThrow(
        InternalServerErrorException
      );
    });
  });
});