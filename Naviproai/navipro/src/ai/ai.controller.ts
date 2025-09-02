import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Logger,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import { AiService } from './ai.service';
import { ChatDto } from './dto/chat.dto';
import { GenerateRoadmapDto } from './dto/generate-roadmap.dto';
import { AuthGuard } from '@nestjs/passport';
import { User as GetUser } from '../user/user.decorator';
import type { User } from '../user/user.schema';
import type { Types } from 'mongoose';

// A more specific type for the user object from the request, including the _id.
type RequestUser = User & { _id: Types.ObjectId };

@Controller('ai')
export class AiController {
  private readonly logger = new Logger(AiController.name);
  constructor(private readonly aiService: AiService) {}

  @Get('health')
  @HttpCode(HttpStatus.OK)
  async checkHealth() {
    this.logger.log('Checking AI agent health');
    return this.aiService.checkHealth();
  }

  @Post('generate-roadmap')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard('jwt'))
  async generateRoadmap(
    @GetUser() user: RequestUser,
    @Body() generateRoadmapDto: GenerateRoadmapDto,
  ) {
    if (!user || !user._id) {
      this.logger.error('User not found in request for generate-roadmap');
      throw new UnauthorizedException('User not found');
    }
    const userId = user._id.toString();
    this.logger.log(`Received request to generate roadmap for user: ${userId}`);
    return this.aiService.generateRoadmap(userId, generateRoadmapDto);
  }

  @Post('chat')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard('jwt'))
  async chat(@GetUser() user: RequestUser, @Body() chatDto: ChatDto) {
    if (!user || !user._id) {
      this.logger.error('User not found in request for chat');
      throw new UnauthorizedException('User not found');
    }
    const userId = user._id.toString();
    this.logger.log(`Received chat message from user: ${userId}`);
    return this.aiService.getChatResponse(userId, chatDto.message);
  }
}
