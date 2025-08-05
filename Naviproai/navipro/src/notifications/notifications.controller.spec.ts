import { Test, TestingModule } from '@nestjs/testing';
import { NotificationsController } from './notifications.controller';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';

describe('NotificationsController', () => {
  let controller: NotificationsController;
  let app: INestApplication;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [NotificationsController],
    }).compile();

    controller = module.get<NotificationsController>(NotificationsController);
    app = module.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should have the correct route prefix', () => {
    const controllerPath = Reflect.getMetadata('path', NotificationsController);
    expect(controllerPath).toBe('notifications');
  });

  it('should return 404 for unimplemented GET /notifications', async () => {
    await request(app.getHttpServer())
      .get('/notifications')
      .expect(404);
  });

  it('should be injectable into other modules', () => {
    expect(controller).toBeInstanceOf(NotificationsController);
  });

  it('should allow future method additions without breaking instantiation', () => {
    expect(() => new NotificationsController()).not.toThrow();
  });
});
