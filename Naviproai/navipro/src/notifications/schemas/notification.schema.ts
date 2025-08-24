import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '../../user/user.schema';

export enum NotificationType {
  PROGRESS_UPDATE = 'progress_update',
  NEW_RECOMMENDATION = 'new_recommendation',
  STREAK_REMINDER = 'streak_reminder',
}

@Schema({ timestamps: true })
export class Notification extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId!: User;

  @Prop({ required: true })
  message!: string;

  @Prop({ required: true, enum: NotificationType })
  type!: NotificationType;

  @Prop({ default: false })
  read!: boolean;
}

export const NotificationSchema = SchemaFactory.createForClass(Notification);