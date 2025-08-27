import { IsString, IsNotEmpty, IsEnum } from 'class-validator';
import { Notification } from '../schemas/notification.schema';

export class CreateNotificationDto {
  @IsString()
  @IsNotEmpty()
  userId!: string;

  @IsString()
  @IsNotEmpty()
  message!: string;

  type!: Notification;
}
