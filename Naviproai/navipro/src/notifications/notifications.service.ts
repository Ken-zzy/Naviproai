import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Notification } from './schemas/notification.schema';
import { CreateNotificationDto } from './dto/create-notification.dto';
import { UserService } from '../user/user.service';
import { EmailService } from '../email/email.service';
import { PushNotificationsService } from '../push-notifications/push-notifications.service';

interface DeliveryOptions {
  sendEmail?: boolean;
  sendPush?: boolean;
}

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);

  constructor(
    @InjectModel(Notification.name)
    private readonly notificationModel: Model<Notification>,
    private readonly userService: UserService,
    private readonly emailService: EmailService,
    private readonly pushService: PushNotificationsService,
  ) {}

  async create(
    createNotificationDto: CreateNotificationDto,
    options: DeliveryOptions = {},
  ): Promise<Notification> {
    // 1. Create the in-app notification and save it to the database.
    const newNotification = new this.notificationModel(createNotificationDto);
    await newNotification.save();

    const user = await this.userService.findById(createNotificationDto.userId);
    if (!user) {
      this.logger.warn(`User not found for notification: ${createNotificationDto.userId}`);
      return newNotification;
    }

    // 2. Dispatch to other channels based on options
    if (options.sendEmail && user.email) {
      try {
        await this.emailService.sendMail({ to: user.email, subject: 'New Notification from NaviPro.ai', text: newNotification.message });
      } catch (error) {
        this.logger.error(`Failed to send email notification to ${user.email}`, error.stack);
      }
    }

    if (options.sendPush && user.pushTokens?.length > 0) {
      try {
        await this.pushService.send(user.pushTokens, { title: 'NaviPro.ai', body: newNotification.message });
      } catch (error) {
        this.logger.error(`Failed to send push notification to user ${user.id}`, error.stack);
      }
    }

    return newNotification;
  }

  async findAllForUser(userId: string): Promise<Notification[]> {
    return this.notificationModel
      .find({ userId })
      .sort({ createdAt: -1 })
      .limit(50) // Return the 50 most recent notifications
      .exec();
  }

  async markAsRead(notificationId: string, userId: string): Promise<Notification | null> {
    return this.notificationModel.findOneAndUpdate(
      { _id: notificationId, userId }, // Ensure user can only mark their own notifications
      { $set: { read: true } },
      { new: true },
    ).exec();
  }

  async markAllAsRead(userId: string) {
    return this.notificationModel.updateMany(
      { userId, read: false },
      { $set: { read: true } },
    ).exec();
  }
}