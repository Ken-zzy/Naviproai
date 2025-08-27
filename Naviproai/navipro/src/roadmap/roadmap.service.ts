import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Roadmap, RoadmapDocument } from './schemas/roadmap.schema';
import { CreateRoadmapDto } from './dto/create-roadmap.dto';

@Injectable()
export class RoadmapService {
  constructor(
    @InjectModel(Roadmap.name) private readonly roadmapModel: Model<RoadmapDocument>,
  ) {}

  async create(createRoadmapDto: CreateRoadmapDto): Promise<RoadmapDocument> {
    const newRoadmap = new this.roadmapModel(createRoadmapDto);
    return newRoadmap.save();
  }
}