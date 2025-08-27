import { Test, TestingModule } from '@nestjs/testing';
import { NotificationsController } from './notifications.controller';
import { NotificationsService } from './notifications.service';

describe('NotificationsController', () => {
  let controller: NotificationsController;
  let service: NotificationsService;

  const mockNotificationsService = {
    findAllForUser: jest.fn().mockResolvedValue([]),
    markAsRead: jest.fn().mockResolvedValue({ read: true }),
    markAllAsRead: jest.fn().mockResolvedValue({ modifiedCount: 1 }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [NotificationsController],
      providers: [
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
      ],
    }).compile();

    controller = module.get<NotificationsController>(NotificationsController);
    service = module.get<NotificationsService>(NotificationsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getMyNotifications', () => {
    it('should call the service to find notifications for a user', async () => {
      const mockReq = { user: { sub: 'user-123', email: 'test@test.com' } };
      await controller.getMyNotifications(mockReq as any);
      expect(service.findAllForUser).toHaveBeenCalledWith(mockReq.user.sub);
    });
  });
});
