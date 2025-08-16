import { IsNotEmpty, IsString } from 'class-validator';

export class GenerateRoadmapDto {
  @IsString()
  @IsNotEmpty()
  targetRole: string;

  @IsString()
  @IsNotEmpty()
  currentLevel: string;
}