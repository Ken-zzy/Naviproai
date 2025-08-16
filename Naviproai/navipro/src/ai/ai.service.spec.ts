import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { AiService } from './ai.service';
import { ConfigService } from '../config/config.service';
import { InternalServerErrorException } from '@nestjs/common';
import { GenerateRoadmapDto } from './dto/generate-roadmap.dto';
import { RoadmapService } from '../roadmap/roadmap.service';
import { UserService } from '../user/user.service';
import { ChatHistory } from './schemas/chat-history.schema';
import { got } from 'got';

const mockedGotPost = jest.mocked(got.post);

describe('AiService', () => {
  let service: AiService;
  let mockJson: jest.Mock; // This will be the mock for the .json() method

  const mockConfigService = {
    aiAgentUrl: 'http://fake-url.com',
    aiAgentKey: 'fake-key',
  };

  const mockRoadmapService = {
    createOrUpdateRoadmap: jest.fn().mockImplementation((userId, data) => Promise.resolve({ userId, ...data })),
    getRoadmapByUserId: jest.fn().mockResolvedValue({ months: [] }),
  };

  const mockUserService = {
    findById: jest.fn().mockResolvedValue({ name: 'Test User' }),
  };

  const mockChatHistoryModel = {
    findOne: jest.fn(),
    // Mock findOneAndUpdate to return an object with an exec method
    findOneAndUpdate: jest.fn().mockReturnValue({
      exec: jest.fn().mockResolvedValue(true),
    }),
  };

  beforeEach(async () => {
    // Reset mocks before each test
    jest.clearAllMocks();

    mockJson = jest.fn();
    mockedGotPost.mockReturnValue({
      json: mockJson,
    } as any);

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
    const dto: GenerateRoadmapDto = { targetRole: 'dev', currentLevel: 'beginner' };

    it('should call got.post with correct parameters and return data', async () => {
      const mockResponse = { roadmap: 'This is the roadmap' };
      mockJson.mockResolvedValue(mockResponse);

      const result = await service.generateRoadmap(userId, dto);

      expect(mockedGotPost).toHaveBeenCalledWith('http://fake-url.com', {
        json: {
          goal: `Create a learning roadmap for a ${dto.currentLevel} to become a ${dto.targetRole}.`,
        },
        headers: {
          Authorization: 'Bearer fake-key',
        },
      });
      expect(mockJson).toHaveBeenCalled();
      expect(mockRoadmapService.createOrUpdateRoadmap).toHaveBeenCalledWith(userId, mockResponse);
      expect(result).toEqual({ userId, ...mockResponse });
    });

    it('should throw an InternalServerErrorException on failure', async () => {
      mockJson.mockRejectedValue(new Error('Network error'));
      await expect(service.generateRoadmap(userId, dto)).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('getChatResponse', () => {
    const userId = 'user-123';
    const message = 'How do I stay motivated?';

    it('should call the AI agent with a context-aware prompt', async () => {
      const mockResponse = { reply: 'You can do it!' };
      mockJson.mockResolvedValue(mockResponse);
      // Ensure findOne returns a query-like object with an exec method
      mockChatHistoryModel.findOne.mockReturnValue({ exec: () => Promise.resolve(null) });

      const result = await service.getChatResponse(userId, message);

      expect(mockUserService.findById).toHaveBeenCalledWith(userId);
      expect(mockRoadmapService.getRoadmapByUserId).toHaveBeenCalledWith(userId);
      expect(mockedGotPost).toHaveBeenCalled();
      expect(result).toEqual(mockResponse);
      expect(mockChatHistoryModel.findOneAndUpdate).toHaveBeenCalled();
      // Ensure the chained exec method was called
      expect(mockChatHistoryModel.findOneAndUpdate().exec).toHaveBeenCalled();
    });
  });
});
