import { Controller, Get, Param, Patch, Request, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { NotificationsService } from './notifications.service';

// Define a type for the request object after JWT validation.
// The `validate` method in `JwtStrategy` returns an object with `userId` and `email`.
interface AuthenticatedRequest {
  user: {
    userId: string;
    email: string;
  };
}

@Controller('notifications')
@UseGuards(AuthGuard('jwt')) // Protect all routes in this controller
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  async getMyNotifications(@Request() req: AuthenticatedRequest) {
    // We get the userId from the JWT payload attached by the AuthGuard.
    // This is more secure than passing the userId in the URL.
    return this.notificationsService.findAllForUser(req.user.userId);
  }

  @Patch(':notificationId/read')
  async markAsRead(@Param('notificationId') notificationId: string, @Request() req: AuthenticatedRequest) {
    return this.notificationsService.markAsRead(notificationId, req.user.userId);
  }

  @Patch('read/all')
  async markAllAsRead(@Request() req: AuthenticatedRequest) {
    return this.notificationsService.markAllAsRead(req.user.userId);
  }
}