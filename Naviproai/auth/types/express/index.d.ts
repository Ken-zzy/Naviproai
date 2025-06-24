// types/express/index.d.ts

import express from 'express';
import { JwtPayload } from '../jwtPayload';
import { Document } from 'mongoose';
import { IUser } from '/Users/nwaka/Desktop/futureflow/futureflowBE/Naviproai/auth/src/models/user.model'; // Adjust if path is different

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload | (Document<unknown, any, IUser> & IUser); // Union type
    }
  }
}
