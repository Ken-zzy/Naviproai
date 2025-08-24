import { Body, Controller, Get, Patch, UseGuards, Request, NotFoundException } from '@nestjs/common';
import { StreakService } from './streak.service';
import { UpdateStreakTypeDto } from './dto/update-streak-type.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('streaks')
@UseGuards(AuthGuard('jwt'))
export class StreakController {
  constructor(private readonly streakService: StreakService) {}

  @Get()
  async getStreak(@Request() req: { user: { id: string } }) {
    const userId = req.user.id;
    return this.streakService.getStreak(userId);
  }

  @Patch('type')
  async setStreakType(
    @Request() req: { user: { id: string } },
    @Body() updateStreakTypeDto: UpdateStreakTypeDto,
  ) {
    const userId = req.user.id;
    const user = await this.streakService.setStreakType(userId, updateStreakTypeDto.streakType);
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }
    return { streakType: user.streakType };
  }
}