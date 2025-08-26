import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument, StreakType } from '../user/user.schema';
@Injectable()
export class StreakService {
  constructor(@InjectModel(User.name) private readonly userModel: Model<UserDocument>) {}

  // ... other methods from your original file

  // The return type must be updated to reflect that it can return null

  async setStreakType(userId: string, streakType: StreakType): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(
        userId,
        { $set: { streakType, currentStreak: 0, lastStreakIncrement: null } },
        { new: true },
      )
      .exec();
  }

  private isStreakBroken(user: UserDocument, now: Date): boolean {
    const last = user.lastStreakIncrement;
    // Add a null check for 'last'
    if (!last) {
      return true; // No last increment means it's broken or new
    }

    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const lastDay = new Date(last.getFullYear(), last.getMonth(), last.getDate());
    const diffDays = (today.getTime() - lastDay.getTime()) / (1000 * 3600 * 24);

    if (user.streakType === StreakType.DAILY) {
      return diffDays > 1;
    }

    if (user.streakType === StreakType.WEEKLY) {
      // 'last' is guaranteed to be a Date here
      const diffWeeks = this.getWeekNumber(now) - this.getWeekNumber(last);
      return diffWeeks > 1 || now.getFullYear() > last.getFullYear();
    }
    return false;
  }

  private canIncrementStreak(user: UserDocument, now: Date): boolean {
    const last = user.lastStreakIncrement;
    // Add a null check for 'last'
    if (!last) {
      return true; // If there's no last increment, we can increment
    }

    // ... logic from your original file
    return false;
  }

  private getWeekNumber(d: Date): number {
    d = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
    d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil(((d.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  }
}