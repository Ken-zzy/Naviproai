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

  /**
   * Updates a user's streak based on the current time and their streak type.
   * This method contains the core logic for streak management.
   */
  async updateStreak(userId: string): Promise<UserDocument> {
    const user = await this.userModel.findById(userId).exec();

    if (!user) {
      throw new NotFoundException(`User with ID "${userId}" not found`);
    }

    const now = new Date();

    // 1. Check if the streak is broken and reset if needed.
    if (this.isStreakBroken(user, now)) {
      user.currentStreak = 0;
    }

    // 2. Check if the user can increment the streak.
    if (!this.canIncrementStreak(user, now)) {
      // If the user can't increment yet (e.g., already did today),
      // just return the user object without making changes.
      return user;
    }

    // 3. Increment the streak and update the last increment time.
    user.currentStreak += 1;
    user.lastStreakIncrement = now;

    // 4. Update the longest streak if the current one is greater.
    if (user.currentStreak > user.longestStreak) {
      user.longestStreak = user.currentStreak;
    }

    // 5. Create a notification for the user.
    await this.notificationsService.create({
      userId,
      message: `You've extended your streak to ${user.currentStreak} days! Keep it up!`,
      type: 'streak_increment',
    });

    return user.save();
  }

  private isStreakBroken(user: UserDocument, now: Date): boolean {
    if (!user.lastStreakIncrement) return false;

    const diffInMs = now.getTime() - user.lastStreakIncrement.getTime();
    const diffInHours = diffInMs / (1000 * 60 * 60);

    const breakThresholdHours = user.streakType === StreakType.WEEKLY ? 24 * 14 : 48;
    return diffInHours > breakThresholdHours;
  }

  private canIncrementStreak(user: UserDocument, now: Date): boolean {
    if (!user.lastStreakIncrement) return true;

    const diffInMs = now.getTime() - user.lastStreakIncrement.getTime();
    const diffInHours = diffInMs / (1000 * 60 * 60);

    const incrementIntervalHours = user.streakType === StreakType.WEEKLY ? 24 * 7 : 24;
    return diffInHours >= incrementIntervalHours;
  }
}