import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  Notification,
  NotificationDocument,
} from './schemas/notification.schema';

@Injectable()
export class NotificationsService {
  constructor(
    @InjectModel(Notification.name)
    private readonly notificationModel: Model<NotificationDocument>,
  ) {}

  async findAllForUser(userId: string): Promise<NotificationDocument[]> {
    return this.notificationModel
      .find({ userId })
      .sort({ createdAt: -1 })
      .exec();
  }

  async create(data: { userId: string; message: string; type?: string }) {
    const newNotification = new this.notificationModel(data);
    return newNotification.save();
  }

  async markAsRead(
    notificationId: string,
    userId: string,
  ): Promise<NotificationDocument | null> {
    return this.notificationModel
      .findOneAndUpdate(
        { _id: notificationId, userId },
        { isRead: true },
        { new: true },
      )
      .exec();
  }

  async markAllAsRead(
    userId: string,
  ): Promise<{ acknowledged: boolean; modifiedCount: number }> {
    const result = await this.notificationModel
      .updateMany({ userId, isRead: false }, { isRead: true })
      .exec();
    return {
      acknowledged: result.acknowledged,
      modifiedCount: result.modifiedCount,
    };
  }
}
