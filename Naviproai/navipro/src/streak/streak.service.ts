import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  User,
  UserDocument,
  StreakType,
} from '../user/user.schema';
import { NotificationsService } from '../notifications/notifications.service';

@Injectable()
export class StreakService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    private readonly notificationsService: NotificationsService,
  ) {}

  async getStreak(
    userId: string,
  ): Promise<{
    currentStreak: number;
    longestStreak: number;
    streakType: StreakType;
  }> {
    const user = await this.userModel
      .findById(userId, 'currentStreak longestStreak streakType')
      .exec();

    if (!user) {
      throw new NotFoundException(`User with ID "${userId}" not found`);
    }

    return {
      currentStreak: user.currentStreak,
      longestStreak: user.longestStreak,
      streakType: user.streakType,
    };
  }

  async setStreakType(
    userId: string,
    streakType: StreakType,
  ): Promise<UserDocument | null> {
    return this.userModel.findByIdAndUpdate(
      userId,
      { streakType },
      { new: true },
    );
  }

  // Example method to demonstrate notification creation
  async updateStreak(userId: string): Promise<UserDocument> {
    const user = await this.userModel.findByIdAndUpdate(
      userId,
      { $inc: { currentStreak: 1 } },
      { new: true },
    ).exec();
 if (!user) {
 throw new NotFoundException(`User with ID "${userId}" not found`);
    }

 await this.notificationsService.create({ userId, message: `Your streak is now ${user.currentStreak}!` });

    return user;
  }
}