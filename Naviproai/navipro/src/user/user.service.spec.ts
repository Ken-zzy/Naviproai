import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { UserService } from './user.service';
import { User, UserDocument } from './user.schema';
import { RoadmapService } from '../roadmap/roadmap.service';

describe('UserService', () => {
  let service: UserService;
  let userModel: Model<UserDocument>;
  let roadmapService: RoadmapService;

  const mockUserModel = {
    findOne: jest.fn(),
    findById: jest.fn(),
    find: jest.fn(),
    save: jest.fn(),
  } as any;

  const mockRoadmapService = {
    create: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getModelToken(User.name),
          useValue: mockUserModel,
        },
        {
          provide: RoadmapService,
          useValue: mockRoadmapService,
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    userModel = module.get<Model<UserDocument>>(getModelToken(User.name));
    roadmapService = module.get<RoadmapService>(RoadmapService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
    expect(userModel).toBeDefined();
  });

  // Add more tests based on your actual service methods
});