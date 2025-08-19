import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum StreakType {
  DAILY = 'DAILY',
  WEEKLY = 'WEEKLY',
}

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: false })
  password?: string;

  @Prop({ default: false })
  isVerified: boolean;

  @Prop({ type: String, default: null })
  verificationToken: string | null;

  @Prop({ type: String, unique: true, sparse: true, default: null })
  googleId: string | null;

  @Prop({ type: String, enum: StreakType, default: StreakType.DAILY })
  streakType: StreakType;

  @Prop({ default: 0 })
  currentStreak: number;

  @Prop({ default: 0 })
  longestStreak: number;

  @Prop({ type: Date, default: null })
  lastStreakIncrement: Date | null;
}

export const UserSchema = SchemaFactory.createForClass(User);