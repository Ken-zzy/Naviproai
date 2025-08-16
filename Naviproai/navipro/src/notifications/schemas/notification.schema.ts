import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';
import { User } from '../../user/user.schema';

export enum NotificationType {
  STREAK_REMINDER = 'streak_reminder',
  NEW_RECOMMENDATION = 'new_recommendation',
  PROGRESS_UPDATE = 'progress_update',
  MOTIVATIONAL_MESSAGE = 'motivational_message',
}

@Schema({ timestamps: true })
export class Notification extends Document {
  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User', required: true, index: true })
  userId: User;

  @Prop({ required: true })
  message: string;

  @Prop({ type: String, enum: NotificationType, required: true })
  type: NotificationType;

  @Prop({ default: false, index: true })
  read: boolean;
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);