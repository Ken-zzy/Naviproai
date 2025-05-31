// types/express/index.d.ts
import UserDocument from '/Users/nwaka/Desktop/futureflow/futureflowBE/auth/src/models/user.model';
import express from 'express';

declare global {
  namespace Express {
    interface Request {
      user?: typeof UserDocument; // or whatever your user type is
    }
  }}
