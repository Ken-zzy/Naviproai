import { IsString, IsNotEmpty, IsEnum } from 'class-validator';
import { NotificationType } from '../schemas/notification.schema';

export class CreateNotificationDto {
  @IsString()
  @IsNotEmpty()
  userId!: string;

  @IsString()
  @IsNotEmpty()
  message!: string;

  @IsEnum(NotificationType)
  type!: NotificationType;
}