import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

export enum AuthProvider {
  GOOGLE = 'google',
  EMAIL = 'email',
}

export enum StreakType {
  DAILY = 'daily',
  WEEKLY = 'weekly',
}

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: false }) // Not required for Google OAuth users
  password?: string;

  @Prop()
  name?: string;

  @Prop({ type: String, required: false, unique: true, sparse: true })
  googleId?: string;

  @Prop({ type: [String], enum: AuthProvider, required: true })
  providers: AuthProvider[];

  @Prop({ default: false })
  isVerified: boolean;

  @Prop({ type: String, default: null, select: false })
  verificationToken: string | null;

  @Prop({ type: String, enum: StreakType, default: StreakType.DAILY })
  streakType: StreakType;

  @Prop({ default: 0 })
  currentStreak: number;

  @Prop({ default: 0 })
  longestStreak: number;

  @Prop()
  lastStreakIncrement: Date;

  @Prop([String])
  pushTokens: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);