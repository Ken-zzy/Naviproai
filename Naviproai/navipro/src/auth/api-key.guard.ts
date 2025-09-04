import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    const xUserId = request.headers['x-user-id'];

    if (!xUserId) {
      throw new UnauthorizedException('X-User-ID header is missing');
    }

    // You might want to add more validation here, e.g., check if the user ID exists in your database
    // For now, we'll just check for its presence.

    // Attach the user ID to the request object for later use in controllers
    request.user = { _id: xUserId }; // Assuming your User decorator expects _id

    return true;
  }
}
