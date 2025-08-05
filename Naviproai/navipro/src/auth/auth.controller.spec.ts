import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            register: jest.fn().mockResolvedValue({ id: 1, email: 'test@example.com' }),
            login: jest.fn().mockResolvedValue({ access_token: 'fake-jwt-token' }),
            validateUser: jest.fn().mockResolvedValue({ _id: '1', email: 'test@example.com' }),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    service = module.get<AuthService>(AuthService);
  });

  it('should register a user', async () => {
    const dto = { email: 'test@example.com', password: '123456' };
    const result = await controller.register(dto);
    expect(result).toEqual({ id: 1, email: 'test@example.com' });
    expect(service.register).toHaveBeenCalledWith(dto);
  });

  it('should login a user', async () => {
    const dto = { email: 'test@example.com', password: '123456' };
    const result = await controller.login(dto);
    expect(result).toEqual({ access_token: 'fake-jwt-token' });
    expect(service.validateUser).toHaveBeenCalledWith(dto.email, dto.password);
  });
});