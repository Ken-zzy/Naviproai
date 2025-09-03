import { IsString, IsNotEmpty } from 'class-validator';

export class GenerateRoadmapDto {
  @IsString()
  @IsNotEmpty()
  targetRole!: string;

  @IsString()
  @IsNotEmpty()
  currentLevel!: string;

  @IsString()
  @IsNotEmpty()
  goal!: string;

  @IsString()
  @IsNotEmpty()
  timeframe!: string;
}
