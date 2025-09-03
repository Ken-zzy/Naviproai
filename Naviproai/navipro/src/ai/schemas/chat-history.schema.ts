import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '../../user/user.schema';

export enum ChatMessageRole {
  USER = 'user',
  ASSISTANT = 'assistant',
}

@Schema({ timestamps: true })
export class ChatMessage {
  @Prop({ required: true, enum: ChatMessageRole })
  role!: ChatMessageRole;

  @Prop({ required: true })
  content!: string;
}

export const ChatMessageSchema = SchemaFactory.createForClass(ChatMessage);

@Schema({ timestamps: true })
export class ChatHistory extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId!: User;

  @Prop({ type: [ChatMessageSchema], default: [] })
  messages!: ChatMessage[];
}

export const ChatHistorySchema = SchemaFactory.createForClass(ChatHistory);
