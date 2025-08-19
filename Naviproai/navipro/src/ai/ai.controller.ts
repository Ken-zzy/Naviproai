import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Logger,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AiService } from './ai.service';
import { ChatDto } from './dto/chat.dto';
import { GenerateRoadmapDto } from './dto/generate-roadmap.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('ai')
export class AiController {
  private readonly logger = new Logger(AiController.name);
  constructor(private readonly aiService: AiService) {}

  @Post('generate_roadmap')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard('jwt'))
  async generateRoadmap(@Request() req, @Body() generateRoadmapDto: GenerateRoadmapDto) {
    const userId = req.user.id;
    this.logger.log(`Received request to generate roadmap for user: ${userId}`);
    return this.aiService.generateRoadmap(userId, generateRoadmapDto);
  }

  @Post('chat')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard('jwt'))
  async chat(@Request() req, @Body() chatDto: ChatDto) {
    const userId = req.user.id;
    this.logger.log(`Received chat message from user: ${userId}`);
    return this.aiService.getChatResponse(userId, chatDto.message);
  }
}
