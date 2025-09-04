import {
  Body,
  Controller,
  Get,
  NotFoundException,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';
import { StreakService } from './streak.service';
import { UpdateStreakTypeDto } from './dto/update-streak-type.dto';

@Controller('streak')
@UseGuards(AuthGuard('jwt'))
export class StreakController {
  constructor(private readonly streakService: StreakService) {}

  @Get()
  async getStreak(@Req() req: Request) {
    const userId = (req.user as any)._id;
    return this.streakService.getStreak(userId);
  }

  @Patch('type')
  async setStreakType(
    @Req() req: Request,
    @Body() updateStreakTypeDto: UpdateStreakTypeDto,
  ) {
    const userId = (req.user as any)._id;
    const user = await this.streakService.setStreakType(
      userId,
      updateStreakTypeDto.streakType,
    );
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }
    return { streakType: user.streakType };
  }
}
