import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  email?: string;
  password?: string;
  googleId?: string;
  name?: string;
}

const UserSchema = new Schema<IUser>({
  email: { type: String, unique: true, sparse: true },
  password: String,
  googleId: String,
  name: String,
});

export default mongoose.model<IUser>('User', UserSchema);
