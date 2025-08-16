import { Body, Controller, Get, Patch, UseGuards, Request } from '@nestjs/common';
import { StreakService } from './streaks.service';
import { UpdateStreakTypeDto } from './dto/update-streak-type.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('streaks')
@UseGuards(AuthGuard('jwt'))
export class StreakController {
  constructor(private readonly streakService: StreakService) {}

  @Get()
  async getStreak(@Request() req) {
    const userId = req.user.id;
    return this.streakService.getStreak(userId);
  }

  @Patch('type')
  async setStreakType(
    @Request() req,
    @Body() updateStreakTypeDto: UpdateStreakTypeDto,
  ) {
    const userId = req.user.id;
    const user = await this.streakService.setStreakType(userId, updateStreakTypeDto.streakType);
    return { streakType: user.streakType };
  }
}