import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';

describe('UserController', () => {
  let controller: UserController;
  let service: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [
        {
          provide: UserService,
          useValue: {
            findAll: jest.fn().mockResolvedValue([{ id: 1, name: 'John Doe' }]),
            findById: jest.fn().mockResolvedValue({ id: 1, name: 'John Doe' }),
          },
        },
      ],
    }).compile();

    controller = module.get<UserController>(UserController);
    service = module.get<UserService>(UserService);
  });

  it('should return all users', async () => {
    const users = await controller.findAll();
    expect(users).toEqual([{ id: 1, name: 'John Doe' }]);
  });

  it('should return a user by ID', async () => {
    const user = await controller.findById('1');
    expect(user).toEqual({ id: 1, name: 'John Doe' });
  });
});