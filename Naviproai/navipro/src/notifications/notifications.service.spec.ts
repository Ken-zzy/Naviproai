import { Test, TestingModule } from '@nestjs/testing';
import { NotificationsService } from './notifications.service';
import { getModelToken } from '@nestjs/mongoose';
import { Notification } from './schemas/notification.schema';
import { UserService } from '../user/user.service';
import { EmailService } from '../email/email.service';
import { PushNotificationsService } from '../push-notifications/push-notifications.service';
import { Model } from 'mongoose';

describe('NotificationsService', () => {
  let service: NotificationsService;
  let notificationModel: Model<Notification>;
  let userService: UserService;
  let emailService: EmailService;
  let pushService: PushNotificationsService;

  // This is a mock of the Mongoose Model constructor.
  // It needs to be a function that can be instantiated with `new`.
  const mockNotificationModel = Object.assign(
    jest.fn().mockImplementation(dto => ({
      ...dto,
      save: jest.fn().mockResolvedValue(dto),
    })),
    { // static methods on the model
      find: jest.fn(),
      findOneAndUpdate: jest.fn(),
      updateMany: jest.fn(),
    },
  );

  const mockUserService = {
    findById: jest.fn(),
  };

  const mockEmailService = {
    sendMail: jest.fn(),
  };

  const mockPushService = {
    send: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NotificationsService,
        { provide: getModelToken(Notification.name), useValue: mockNotificationModel },
        { provide: UserService, useValue: mockUserService },
        { provide: EmailService, useValue: mockEmailService },
        { provide: PushNotificationsService, useValue: mockPushService },
      ],
    }).compile();

    service = module.get<NotificationsService>(NotificationsService);
    notificationModel = module.get<Model<Notification>>(getModelToken(Notification.name));
    userService = module.get<UserService>(UserService);
    emailService = module.get<EmailService>(EmailService);
    pushService = module.get<PushNotificationsService>(PushNotificationsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create an in-app notification and send email and push notifications', async () => {
      const dto = { userId: '123', message: 'Test', type: 'progress_update' as any };
      const user = { email: 'test@test.com', pushTokens: ['token1'] };
      mockUserService.findById.mockResolvedValue(user);

      await service.create(dto);

      expect(notificationModel).toHaveBeenCalledWith(dto);
      expect(emailService.sendMail).toHaveBeenCalled();
      expect(pushService.send).toHaveBeenCalledWith(user.pushTokens, expect.any(Object));
    });
  });
});
