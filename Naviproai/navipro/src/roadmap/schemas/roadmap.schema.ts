import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '../../user/user.schema';

@Schema({ _id: false })
export class Task {
  @Prop({ required: true })
  task_id!: string;

  @Prop({ required: true })
  title!: string;

  @Prop({ required: true })
  description!: string;

  @Prop({ type: [String], default: [] })
  resources!: string[];

  @Prop({ required: true })
  day!: number;

  @Prop({ required: true })
  estimated_time!: string;

  @Prop({ default: false })
  completed!: boolean;

  @Prop({ type: Date, default: null })
  completed_date!: Date | null;
}
export const TaskSchema = SchemaFactory.createForClass(Task);

@Schema({ _id: false })
export class Week {
  @Prop({ required: true })
  focus!: string;

  @Prop({ type: [TaskSchema], default: [] })
  daily_tasks!: Task[];
}
export const WeekSchema = SchemaFactory.createForClass(Week);

@Schema({ _id: false })
export class Month {
  @Prop({ type: [WeekSchema], default: [] })
  weeks!: Week[];
}
export const MonthSchema = SchemaFactory.createForClass(Month);

export type RoadmapDocument = Roadmap & Document;

@Schema({ timestamps: true })
export class Roadmap {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, unique: true })
  userId!: User;

  @Prop({ type: [MonthSchema], default: [] })
  months!: Month[];
}

export const RoadmapSchema = SchemaFactory.createForClass(Roadmap);
