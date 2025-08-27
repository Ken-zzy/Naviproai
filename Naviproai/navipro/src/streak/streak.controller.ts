import {
  Body,
  Controller,
  Get,
  Patch,
  UseGuards,
  Req,
  NotFoundException,
} from '@nestjs/common';
import { StreakService } from './streak.service';
import { UpdateStreakTypeDto } from './dto/update-streak-type.dto';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';

@Controller('streak')
@UseGuards(AuthGuard('jwt'))
export class StreakController {
  constructor(private readonly streakService: StreakService) {}

  @Get()
  async getStreak(@Req() req: Request) {
    const userId = (req.user as any).sub;
    return this.streakService.getStreak(userId);
  }

  @Patch('type')
  async setStreakType(
    @Req() req: Request,
    @Body() updateStreakTypeDto: UpdateStreakTypeDto,
  ) {
    const userId = (req.user as any).sub;
    const user = await this.streakService.setStreakType(userId, updateStreakTypeDto.streakType);
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }
    return { streakType: user.streakType };
  }
}