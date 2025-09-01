import { Injectable, Logger, InternalServerErrorException, OnModuleInit } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ConfigService } from '../config/config.service';
import { RoadmapService } from '../roadmap/roadmap.service';
import { UserService } from '../user/user.service';
import { ChatHistory, ChatMessageRole } from './schemas/chat-history.schema';
import type { default as got } from 'got';

type Got = ReturnType<typeof got.extend>;

@Injectable()
export class AiService implements OnModuleInit {
  private readonly logger = new Logger(AiService.name);
  private readonly MAX_CHAT_HISTORY = 20;
  private gotInstance!: Got;

  constructor(
    @InjectModel(ChatHistory.name) private readonly chatHistoryModel: Model<ChatHistory>,
    private readonly configService: ConfigService,
    private readonly roadmapService: RoadmapService,
    private readonly userService: UserService,
  ) {}

  async onModuleInit() {
    // Dynamically import got to avoid issues with CommonJS/ESM module resolution and jest mocking.
    const { default: got } = await import('got');
    this.gotInstance = got.extend({
        timeout: { request: 30000 }, // 30 second timeout
        retry: {
            limit: 3,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
            statusCodes: [408, 413, 429, 500, 502, 503, 504],
        },
    });
  }

  private async _callAiAgent<T>(
    method: 'get' | 'post' | 'patch',
    endpoint: string,
    options: any = {},
  ): Promise<T> {
    const url = `${this.configService.aiAgentUrl}${endpoint}`;

    try {
      let responsePromise;
      switch (method) {
        case 'get':
          responsePromise = this.gotInstance.get(url, options);
          break;
        case 'post':
          responsePromise = this.gotInstance.post(url, options);
          break;
        case 'patch':
          responsePromise = this.gotInstance.patch(url, options);
          break;
      }
      const response = await responsePromise.json<T>();
      this.logger.log(
        `Successfully called AI agent at ${method.toUpperCase()} ${endpoint}`,
      );
      return response;
    } catch (error) {
      this.logger.error(
        `Failed to call AI agent at ${method.toUpperCase()} ${endpoint}`,
        error instanceof Error ? error.stack : String(error),
      );
      throw new InternalServerErrorException(
        'Failed to communicate with AI agent.',
      );
    }
  }

  async generateRoadmap(userId: string, generateRoadmapDto: any) {
    const { targetRole, currentLevel } = generateRoadmapDto;
    this.logger.log(
      `Generating roadmap for role: ${targetRole} from level: ${currentLevel}`,
    );
    const response = await this._callAiAgent<any>('post', `/api/generate_roadmap/${userId}`, {
      json: { targetRole, currentLevel },
    });
    this.logger.log('Successfully received roadmap from AI agent.');
    return this.roadmapService.createOrUpdateRoadmap(userId, response);
  }

  async getChatResponse(userId: string, message: string): Promise<any> {
    this.logger.log(`Getting chat response for user ${userId}`);

    const [user, roadmap, history] = await Promise.all([
      this.userService.findById(userId),
      this.roadmapService.getRoadmapByUserId(userId),
      this.chatHistoryModel.findOne({ userId }).exec(),
    ]);

    if (!user || !roadmap) {
      throw new InternalServerErrorException(
        'User or roadmap data not found to create chat context.',
      );
    }

    const chatContext = {
      userName: user.name || 'User',
      userGoal:
        roadmap.months?.[0]?.weeks?.[0]?.focus || 'professional in their field',
      history:
        history?.messages.map((m) => ({ role: m.role, content: m.content })) ||
        [],
    };

    const aiResponse = await this._callAiAgent<any>(
      'post',
      `/api/chat/${userId}`,
      {
        json: {
          message,
          context: chatContext,
        },
      },
    );

    const replyContent =
      aiResponse.reply || aiResponse.text || JSON.stringify(aiResponse);

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
  }

  async getUserRoadmap(userId: string): Promise<any> {
    this.logger.log(`Getting user roadmap from AI for user ${userId}`);
    return this._callAiAgent<any>('get', `/api/user_roadmap/${userId}`);
  }

  async completeTask(userId: string, taskId: string): Promise<any> {
    this.logger.log(`Completing task ${taskId} for user ${userId} via AI`);
    return this._callAiAgent<any>('patch', `/api/complete_task/${userId}`, {
      json: { taskId },
    });
  }

  async getUserProgress(userId: string): Promise<any> {
    this.logger.log(`Getting user progress from AI for user ${userId}`);
    return this._callAiAgent<any>('get', `/api/user_progress/${userId}`);
  }

  async getWeeklyVideos(userId: string): Promise<any> {
    this.logger.log(`Getting weekly videos from AI for user ${userId}`);
    return this._callAiAgent<any>('get', `/api/week_videos/${userId}`);
  }
  
  async triggerFullPipeline(): Promise<any> {
    this.logger.log('Triggering full pipeline on AI agent');
    return this._callAiAgent<any>('post', '/api/full_pipeline');
  }

  async checkHealth(): Promise<any> {
    this.logger.log('Checking AI agent health');
    return this._callAiAgent<any>('get', '/api/health');
  }
}