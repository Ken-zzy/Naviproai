import {
  Controller,
  Get,
  NotFoundException,
  Param,
  Patch,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';
import { NotificationsService } from './notifications.service';

@Controller('notifications')
@UseGuards(AuthGuard('jwt'))
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  async getMyNotifications(@Req() req: Request) {
    // The JWT strategy attaches the user payload to the request.
    // The spec file indicates the user ID is on `req.user.userId`.
    const userId = (req.user as any).userId;
    return this.notificationsService.findAllForUser(userId);
  }

  @Patch(':id/read')
  async markAsRead(@Param('id') notificationId: string, @Req() req: Request) {
    const userId = (req.user as any).userId;
    const notification = await this.notificationsService.markAsRead(
      notificationId,
      userId,
    );
    if (!notification) {
      throw new NotFoundException(
        `Notification with ID "${notificationId}" not found or you don't have permission to access it.`,
      );
    }
    return notification;
  }

  @Patch('read-all')
  async markAllAsRead(@Req() req: Request) {
    const userId = (req.user as any).userId;
    return this.notificationsService.markAllAsRead(userId);
  }
}