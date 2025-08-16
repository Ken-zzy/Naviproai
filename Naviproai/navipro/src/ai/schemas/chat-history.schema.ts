import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';
import { User } from '../../user/user.schema';

export enum ChatMessageRole {
  USER = 'user',
  ASSISTANT = 'assistant',
}

@Schema({ _id: false })
export class ChatMessage {
  @Prop({ type: String, enum: ChatMessageRole, required: true })
  role: ChatMessageRole;

  @Prop({ required: true })
  content: string;
}
export const ChatMessageSchema = SchemaFactory.createForClass(ChatMessage);

@Schema({ timestamps: true })
export class ChatHistory extends Document {
  @Prop({ type: MongooseSchema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true })
  userId: User;

  @Prop({ type: [ChatMessageSchema], default: [] })
  messages: ChatMessage[];
}

export const ChatHistorySchema = SchemaFactory.createForClass(ChatHistory);