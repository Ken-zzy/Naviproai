import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

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

  describe('register', () => {
    it('should call authService.register with the correct DTO', async () => {
      const dto: RegisterDto = { name: 'Test User', email: 'test@example.com', password: '123456' };
      await controller.register(dto);
      expect(service.register).toHaveBeenCalledWith(dto);
    });
  });

  describe('login', () => {
    it('should call authService.login after validating the user', async () => {
      const dto: LoginDto = { email: 'test@example.com', password: '123456' };
      const mockUser = { _id: '1', email: 'test@example.com' };
      (service.validateUser as jest.Mock).mockResolvedValue(mockUser);
      await controller.login(dto);
      expect(service.validateUser).toHaveBeenCalledWith(dto.email, dto.password);
      expect(service.login).toHaveBeenCalledWith(mockUser);
    });
  });
});