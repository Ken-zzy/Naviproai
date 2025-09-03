import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserDocument } from '../user/user.schema';

export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): UserDocument => {
    const request = ctx.switchToHttp().getRequest();
    // The user object is attached by the Passport JWT strategy
    return request.user;
  },
);
