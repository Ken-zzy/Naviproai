import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { User } from '../../user/user.schema';

@Schema({ _id: false }) // Subdocuments don't need their own _id
export class Task {
  @Prop({ required: true })
  task_id!: string;

  @Prop({ required: true })
  goal!: string;

  @Prop({ required: true })
  estimated_time!: string;

  @Prop({ type: [String], default: [] })
  resources!: string[];

  @Prop({ default: false })
  completed!: boolean;

  @Prop({ type: Date, default: null })
  completed_date!: Date | null;
}
export const TaskSchema = SchemaFactory.createForClass(Task);

@Schema({ _id: false })
export class Week {
  @Prop({ required: true })
  week_number!: number;

  @Prop({ required: true })
  focus!: string;

  @Prop({ type: [TaskSchema], default: [] })
  daily_tasks!: Task[];
}
export const WeekSchema = SchemaFactory.createForClass(Week);

@Schema({ _id: false })
export class Month {
  @Prop({ required: true })
  month_number!: number;

  @Prop({ type: [WeekSchema], default: [] })
  weeks!: Week[];
}
export const MonthSchema = SchemaFactory.createForClass(Month);

@Schema({ timestamps: true })
export class Roadmap extends Document {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true, unique: true, index: true })
  userId!: User;

  @Prop({ type: [MonthSchema], default: [] })
  months!: Month[];
}

export const RoadmapSchema = SchemaFactory.createForClass(Roadmap);