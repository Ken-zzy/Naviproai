import { Controller, Get, Param, UseGuards, Req } from '@nestjs/common';
import { UserService } from './user.service';
import { User, UserDocument } from './user.schema';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';

@Controller('user')
@UseGuards(AuthGuard('jwt')) // Protect all routes in this controller
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('me')
  getProfile(@Req() req: Request) {
    // The JWT strategy attaches the user payload to the request object.
    // It's good practice to ensure the password is not included in the payload.
    return req.user;
  }

  @Get()
  findAll() {
    return this.userService.findAll();
  }

  @Get(':id')
  async findById(@Param('id') id: string): Promise<UserDocument | null> {
    return this.userService.findById(id);
  }
}
