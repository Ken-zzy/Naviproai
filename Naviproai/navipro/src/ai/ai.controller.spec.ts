import { Test, TestingModule } from '@nestjs/testing';
import { AiController } from './ai.controller';
import { AiService } from './ai.service';
import { GenerateRoadmapDto } from './dto/generate-roadmap.dto';
import { ChatDto } from './dto/chat.dto';

describe('AiController', () => {
  let controller: AiController;
  let service: AiService;

  const mockAiService = {
    generateRoadmap: jest.fn(),
    getChatResponse: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AiController],
      providers: [
        {
          provide: AiService,
          useValue: mockAiService,
        },
      ],
    }).compile();

    controller = module.get<AiController>(AiController);
    service = module.get<AiService>(AiService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('generateRoadmap', () => {
    it('should call aiService.generateRoadmap with the correct DTO', async () => {
      const mockReq = { user: { id: 'user-123' } };
      const dto: GenerateRoadmapDto = { targetRole: 'dev', currentLevel: 'beginner' };
      mockAiService.generateRoadmap.mockResolvedValue({ success: true });
      await controller.generateRoadmap(mockReq, dto);
      expect(service.generateRoadmap).toHaveBeenCalledWith(mockReq.user.id, dto);
    });
  });

  describe('chat', () => {
    it('should call aiService.getChatResponse with the correct params', async () => {
      const mockReq = { user: { id: 'user-123' } };
      const dto: ChatDto = { message: 'Hello' };
      mockAiService.getChatResponse.mockResolvedValue({ reply: 'Hi' });
      await controller.chat(mockReq, dto);
      expect(service.getChatResponse).toHaveBeenCalledWith(mockReq.user.id, dto.message);
    });
  });
});
