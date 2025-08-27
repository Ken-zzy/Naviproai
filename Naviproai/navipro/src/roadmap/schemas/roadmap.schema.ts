import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '../../user/user.schema';

export type RoadmapDocument = Roadmap & Document;

@Schema({ timestamps: true })
export class Roadmap {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, unique: true })
  userId!: User;
}

export const RoadmapSchema = SchemaFactory.createForClass(Roadmap);