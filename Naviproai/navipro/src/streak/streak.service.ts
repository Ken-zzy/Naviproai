import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, StreakType, UserDocument } from '../user/user.schema';

@Injectable()
export class StreakService {
  constructor(@InjectModel(User.name) private readonly userModel: Model<UserDocument>) {}

  /**
   * Updates a user's streak. This should be called from your RoadmapService
   * whenever a user successfully completes a task.
   * @param userId The ID of the user.
   */
  async updateStreak(userId: string): Promise<UserDocument> {
    const user = await this.userModel.findById(userId).exec();
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    const now = new Date();
    let needsSave = false;

    if (!user.lastStreakIncrement || this.isStreakBroken(user, now)) {
      // Streak was broken or it's the first task, reset to 1
      user.currentStreak = 1;
      needsSave = true;
    } else if (this.canIncrementStreak(user, now)) {
      // It's a new day/week, increment the streak
      user.currentStreak += 1;
      needsSave = true;
    }
    // If canIncrementStreak is false, a task was already completed in the current period. Do nothing.

    if (needsSave) {
      user.lastStreakIncrement = now;
      if (user.currentStreak > user.longestStreak) {
        user.longestStreak = user.currentStreak;
      }
      return user.save();
    }

    return user;
  }

  /**
   * Gets the current streak data for a user.
   * @param userId The ID of the user.
   */
  async getStreak(userId: string): Promise<{ currentStreak: number; longestStreak: number; streakType: StreakType }> {
    const user = await this.userModel.findById(userId).exec();
    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    // Before returning, check if the streak is broken and reset if necessary
    if (user.lastStreakIncrement && this.isStreakBroken(user, new Date())) {
      user.currentStreak = 0;
      await user.save();
    }

    return {
      currentStreak: user.currentStreak,
      longestStreak: user.longestStreak,
      streakType: user.streakType,
    };
  }

  async setStreakType(userId: string, streakType: StreakType): Promise<UserDocument | null> {
    return this.userModel.findByIdAndUpdate(
      userId,
      { $set: { streakType, currentStreak: 0, lastStreakIncrement: null } },
      { new: true },
    ).exec();
  }

  private isStreakBroken(user: UserDocument, now: Date): boolean {
    const last = user.lastStreakIncrement;
    if (!last) {
      // This case is logically handled by the callers, but this check satisfies TypeScript
      // and prevents runtime errors if the method is ever called directly without a guard.
      // If there's no last date, the streak isn't "broken", it just hasn't started.
      return false;
    }
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const lastDay = new Date(last.getFullYear(), last.getMonth(), last.getDate());

    const diffDays = (today.getTime() - lastDay.getTime()) / (1000 * 3600 * 24);

    if (user.streakType === StreakType.DAILY) {
      return diffDays > 1;
    }

    if (user.streakType === StreakType.WEEKLY) {
      const diffWeeks = this.getWeekNumber(now) - this.getWeekNumber(last);
      return diffWeeks > 1 || now.getFullYear() > last.getFullYear();
    }

    return false;
  }

  private canIncrementStreak(user: UserDocument, now: Date): boolean {
    const last = user.lastStreakIncrement;
    if (!last) {
      return true;
    }
    if (user.streakType === StreakType.DAILY) {
      return now.toDateString() !== last.toDateString();
    }
    if (user.streakType === StreakType.WEEKLY) {
      return this.getWeekNumber(now) !== this.getWeekNumber(last) || now.getFullYear() !== last.getFullYear();
    }
    return false;
  }

  private getWeekNumber(d: Date): number {
    d = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
    d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil(((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  }
}