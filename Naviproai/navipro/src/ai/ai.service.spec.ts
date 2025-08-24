import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { AiService } from './ai.service';
import { ConfigService } from '../config/config.service';
import { InternalServerErrorException } from '@nestjs/common';
import { RoadmapService } from '../roadmap/roadmap.service';
import { UserService } from '../user/user.service';
import { ChatHistory } from './schemas/chat-history.schema';
import got from 'got';

// Mock the 'got' module
jest.mock('got');

const mockedGot = got as jest.Mocked<typeof got>;

describe('AiService', () => {
  let service: AiService;

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
    findOne: jest.fn(),
    findOneAndUpdate: jest.fn().mockReturnValue({
      exec: jest.fn().mockResolvedValue(true),
    }),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

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
      mockedGot.post.mockReturnValue({
        json: mockJsonResponse,
      } as any);

      const result = await service.generateRoadmap(userId, dto);

      expect(mockedGot.post).toHaveBeenCalledWith('http://fake-url.com', {
        json: {
          goal: `Create a learning roadmap for a ${dto.currentLevel} to become a ${dto.targetRole}.`,
        },
        headers: {
          Authorization: 'Bearer fake-key',
        },
      });
      expect(mockJsonResponse).toHaveBeenCalled();
      expect(mockRoadmapService.createOrUpdateRoadmap).toHaveBeenCalledWith(userId, mockResponse);
      expect(result).toEqual({ userId, ...mockResponse });
    });

    it('should throw an InternalServerErrorException on failure', async () => {
      mockedGot.post.mockImplementation(() => {
        return Promise.reject(new Error('Network error'));
      });
      await expect(service.generateRoadmap(userId, dto)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});