import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

export enum AuthProvider {
  GOOGLE = 'google',
  EMAIL = 'email',
}

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

  @Prop({ type: [String], enum: AuthProvider, required: true })
  providers: AuthProvider[];

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

  @Prop({ type: [String], default: [] })
  pushTokens: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);