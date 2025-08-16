import { Controller, Get, Param, Patch, Request, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { NotificationsService } from './notifications.service';

@Controller('notifications')
@UseGuards(AuthGuard('jwt')) // Protect all routes in this controller
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  async getMyNotifications(@Request() req) {
    // We get the userId from the JWT payload attached by the AuthGuard.
    // This is more secure than passing the userId in the URL.
    const userId = req.user.id;
    return this.notificationsService.findAllForUser(userId);
  }

  @Patch(':notificationId/read')
  async markAsRead(@Param('notificationId') notificationId: string, @Request() req) {
    const userId = req.user.id;
    return this.notificationsService.markAsRead(notificationId, userId);
  }

  @Patch('read/all')
  async markAllAsRead(@Request() req) {
    const userId = req.user.id;
    return this.notificationsService.markAllAsRead(userId);
  }
}