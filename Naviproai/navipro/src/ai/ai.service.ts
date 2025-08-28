import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ConfigService } from '../config/config.service';
import { GenerateRoadmapDto } from './dto/generate-roadmap.dto';
import { RoadmapService } from '../roadmap/roadmap.service';
import { UserService } from '../user/user.service';
import { ChatHistory, ChatMessageRole } from './schemas/chat-history.schema';

@Injectable()
export class AiService {
  private readonly logger = new Logger(AiService.name);
  private readonly MAX_CHAT_HISTORY = 20;

  constructor(
    @InjectModel(ChatHistory.name) private readonly chatHistoryModel: Model<ChatHistory>,
    private readonly configService: ConfigService,
    private readonly roadmapService: RoadmapService,
    private readonly userService: UserService,
  ) {}

  async generateRoadmap(userId: string, generateRoadmapDto: GenerateRoadmapDto): Promise<any> {
    const { targetRole, currentLevel } = generateRoadmapDto;
    const aiAgentUrl = this.configService.aiAgentUrl;
    const aiAgentKey = this.configService.aiAgentKey;

    this.logger.log(
      `Generating roadmap for role: ${targetRole} from level: ${currentLevel}`,
    );

    try {
      const got = (await import('got')).default;
      // Assuming aiAgentUrl is the base URL, we append the specific endpoint path.
      const roadmapAgentUrl = `${aiAgentUrl}/api/generate_roadmap`;

      const response = await got.post(roadmapAgentUrl, {
        json: {
          // Send structured data instead of a formatted string.
          targetRole,
          currentLevel,
        },
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();

      this.logger.log('Successfully received roadmap from AI agent.');

      const savedRoadmap = await this.roadmapService.createOrUpdateRoadmap(userId, response);
      return savedRoadmap;
    } catch (error) {
      this.logger.error(
        'Failed to generate roadmap from AI agent',
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('Failed to generate learning roadmap.');
    }
  }

  async getChatResponse(userId: string, message: string): Promise<any> {
    this.logger.log(`Getting chat response for user ${userId}`);

    const user = await this.userService.findById(userId);
    const roadmap = await this.roadmapService.getRoadmapByUserId(userId);
    const history = await this.chatHistoryModel.findOne({ userId }).exec();

    if (!user || !roadmap) {
      throw new InternalServerErrorException('User or roadmap data not found to create chat context.');
    }

    // Construct a structured context object instead of a single prompt string.
    // This makes the API contract with the AI agent clearer and more robust.
    const chatContext = {
      userName: user.name || 'User',
      userGoal: roadmap.months[0]?.weeks[0]?.focus || 'professional in their field',
      history: history?.messages.map(m => ({ role: m.role, content: m.content })) || [],
    };

    try {
      const got = (await import('got')).default;
      // The user's ID is passed in the URL as per your endpoint design.
      const chatAgentUrl = `${this.configService.aiAgentUrl}/api/chat/${userId}`;

      const aiResponse = await got.post(chatAgentUrl, {
        json: {
          message,
          context: chatContext,
        },
        headers: {
          Authorization: `Bearer ${this.configService.aiAgentKey}`,
        },
      }).json<any>();

      // The structure of the AI response might change with the new endpoint.
      // Assuming it still returns a text reply in a property like 'reply' or 'text'.
      const replyContent = aiResponse.reply || aiResponse.text || JSON.stringify(aiResponse);

      await this.chatHistoryModel.findOneAndUpdate(
        { userId },
        {
          $push: {
            messages: {
              $each: [
                { role: ChatMessageRole.USER, content: message },
                { role: ChatMessageRole.ASSISTANT, content: replyContent },
              ],
              $slice: -this.MAX_CHAT_HISTORY,
            },
          },
        },
        { upsert: true, new: true },
      ).exec();

      return aiResponse;
    } catch (error) {
      this.logger.error(
        'Failed to get chat response from AI agent',
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('Failed to get chat response.');
    }
  }

  async getUserRoadmap(userId: string): Promise<any> {
    this.logger.log(`Getting user roadmap from AI for user ${userId}`);
    const aiAgentUrl = this.configService.aiAgentUrl;
    const aiAgentKey = this.configService.aiAgentKey;
    const url = `${aiAgentUrl}/api/user_roadmap/${userId}`;

    try {
      const got = (await import('got')).default;
      const response = await got.get(url, {
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();
      this.logger.log(`Successfully received user roadmap from AI for user ${userId}`);
      return response;
    } catch (error) {
      this.logger.error(
        `Failed to get user roadmap from AI for user ${userId}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('Failed to get user roadmap.');
    }
  }

  async completeTask(userId: string, taskId: string): Promise<any> {
    this.logger.log(`Completing task ${taskId} for user ${userId} via AI`);
    const aiAgentUrl = this.configService.aiAgentUrl;
    const aiAgentKey = this.configService.aiAgentKey;
    const url = `${aiAgentUrl}/api/complete_task/${userId}`;

    try {
      const got = (await import('got')).default;
      const response = await got.patch(url, { // Using PATCH as it's an update
        json: { taskId },
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();
      this.logger.log(`Successfully completed task ${taskId} for user ${userId} via AI`);
      return response;
    } catch (error) {
      this.logger.error(
        `Failed to complete task via AI for user ${userId}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('Failed to complete task.');
    }
  }

  async getUserProgress(userId: string): Promise<any> {
    this.logger.log(`Getting user progress from AI for user ${userId}`);
    const aiAgentUrl = this.configService.aiAgentUrl;
    const aiAgentKey = this.configService.aiAgentKey;
    const url = `${aiAgentUrl}/api/user_progress/${userId}`;

    try {
      const got = (await import('got')).default;
      const response = await got.get(url, {
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();
      this.logger.log(`Successfully received user progress from AI for user ${userId}`);
      return response;
    } catch (error) {
      this.logger.error(
        `Failed to get user progress from AI for user ${userId}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('Failed to get user progress.');
    }
  }

  async getWeeklyVideos(userId: string): Promise<any> {
    this.logger.log(`Getting weekly videos from AI for user ${userId}`);
    const aiAgentUrl = this.configService.aiAgentUrl;
    const aiAgentKey = this.configService.aiAgentKey;
    const url = `${aiAgentUrl}/api/week_videos/${userId}`;

    try {
      const got = (await import('got')).default;
      const response = await got.get(url, {
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();
      this.logger.log(`Successfully received weekly videos from AI for user ${userId}`);
      return response;
    } catch (error) {
      this.logger.error(
        `Failed to get weekly videos from AI for user ${userId}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('Failed to get weekly videos.');
    }
  }

  async triggerFullPipeline(): Promise<any> {
    this.logger.log('Triggering full pipeline on AI agent');
    const aiAgentUrl = this.configService.aiAgentUrl;
    const aiAgentKey = this.configService.aiAgentKey;
    const url = `${aiAgentUrl}/api/full_pipeline`;

    try {
      const got = (await import('got')).default;
      const response = await got.post(url, { // Assuming POST for a pipeline trigger
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();
      this.logger.log('Successfully triggered full pipeline on AI agent');
      return response;
    } catch (error) {
      this.logger.error(
        'Failed to trigger full pipeline on AI agent',
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('Failed to trigger full pipeline.');
    }
  }

  async checkHealth(): Promise<any> {
    this.logger.log('Checking AI agent health');
    const aiAgentUrl = this.configService.aiAgentUrl;
    const aiAgentKey = this.configService.aiAgentKey;
    const url = `${aiAgentUrl}/api/health`;

    try {
      const got = (await import('got')).default;
      const response = await got.get(url, {
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();
      this.logger.log('AI agent health check successful');
      return response;
    } catch (error) {
      this.logger.error(
        'AI agent health check failed',
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException('AI agent health check failed.');
    }
  }
}
