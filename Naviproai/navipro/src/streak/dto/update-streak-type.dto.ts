import { IsEnum } from 'class-validator';
import { StreakType } from '../../user/user.schema';

export class UpdateStreakTypeDto {
  @IsEnum(StreakType)
  streakType: StreakType;
}