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
    // The user's ID is in the 'sub' (subject) claim of the JWT payload.
    const userId = (req.user as any).sub;
    return this.notificationsService.findAllForUser(userId);
  }

  @Patch(':id/read')
  async markAsRead(@Param('id') notificationId: string, @Req() req: Request) {
    const userId = (req.user as any).sub;
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
    const userId = (req.user as any).sub;
    return this.notificationsService.markAllAsRead(userId);
  }
}