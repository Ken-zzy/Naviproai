import { IsString, IsNotEmpty } from 'class-validator';

export class GenerateRoadmapDto {
  @IsString()
  @IsNotEmpty()
  targetRole!: string;

  @IsString()
  @IsNotEmpty()
  currentLevel!: string;
}
