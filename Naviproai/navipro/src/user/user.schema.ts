import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export enum AuthProvider {
  EMAIL = 'email',
  GOOGLE = 'google',
}

export enum StreakType {
  DAILY = 'daily',
  WEEKLY = 'weekly',
}

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true })
  name!: string;

  @Prop({ required: true, unique: true, index: true })
  email!: string;

  @Prop()
  password?: string;

  @Prop({ type: [String], enum: AuthProvider, required: true })
  providers!: AuthProvider[];

  @Prop({ default: false })
  isVerified!: boolean;

  @Prop({ default: null })
  verificationToken!: string | null;

  @Prop({ default: null, unique: true, sparse: true })
  googleId!: string | null;

  @Prop({ enum: StreakType, default: StreakType.DAILY })
  streakType!: StreakType;

  @Prop({ default: 0 })
  currentStreak!: number;

  @Prop({ default: 0 })
  longestStreak!: number;

  @Prop({ type: Date, default: null })
  lastStreakIncrement!: Date | null;

  @Prop({ type: [String], default: [] })
  pushTokens!: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);