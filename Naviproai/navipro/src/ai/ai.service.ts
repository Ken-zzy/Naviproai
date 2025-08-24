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
      // Correctly import the default export from ESM-only 'got' package
      const got = (await import('got')).default;
      const response = await got.post(aiAgentUrl, {
        json: {
          goal: `Create a learning roadmap for a ${currentLevel} to become a ${targetRole}.`,
        },
        headers: {
          Authorization: `Bearer ${aiAgentKey}`,
        },
      }).json<any>();

      this.logger.log('Successfully received roadmap from AI agent.');

      // Save the generated roadmap to the user's profile
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

    const contextPrompt = `
      You are a motivational and supportive AI learning assistant named Navi.
      A user is asking you a question. Use the following context to inform your response.
      - User's Name: ${user.name || 'User'}
      - User's Goal: To become a ${roadmap.months[0]?.weeks[0]?.focus || 'professional in their field'}.
      - Recent Conversation History:
        ${history?.messages.map(m => `${m.role}: ${m.content}`).join('\n') || 'No recent history.'}

      User's message: "${message}"

      Your response should be helpful, encouraging, and directly related to their learning journey.
    `;

    try {
      // Correctly import the default export from ESM-only 'got' package
      const got = (await import('got')).default;
      const aiResponse = await got.post(this.configService.aiAgentUrl, {
        json: {
          goal: contextPrompt,
        },
        headers: {
          Authorization: `Bearer ${this.configService.aiAgentKey}`,
        },
      }).json<any>();

      // Save the new messages to the history, keeping only the last N messages.
      // Note: `aiResponse.reply` assumes your AI agent returns an object with a `reply` property.
      // You may need to adjust this based on the actual shape of the AI's response.
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
}
