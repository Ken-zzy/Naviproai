import {
  Controller,
  Get,
  NotFoundException,
  Param,
  Patch,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { NotificationsService } from './notifications.service';
import { User } from '../user/user.decorator';

// Define a type for the user payload attached by the JWT strategy.
// This makes the code more type-safe and self-documenting.
interface AuthenticatedUser {
  sub: string; // 'sub' is the standard claim for subject (user ID) in a JWT
  email: string;
  // Add other properties from your JWT payload if they exist
}

@Controller('notifications')
@UseGuards(AuthGuard('jwt'))
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  async getMyNotifications(@User() user: AuthenticatedUser) {
    return this.notificationsService.findAllForUser(user.sub);
  }

  @Patch(':id/read')
  async markAsRead(
    @Param('id') notificationId: string,
    @User() user: AuthenticatedUser,
  ) {
    const notification = await this.notificationsService.markAsRead(
      notificationId,
      user.sub,
    );
    if (!notification) {
      throw new NotFoundException(
        `Notification with ID "${notificationId}" not found or you don't have permission to access it.`,
      );
    }
    return notification;
  }

  @Patch('read-all')
  async markAllAsRead(@User() user: AuthenticatedUser) {
    return this.notificationsService.markAllAsRead(user.sub);
  }
}
