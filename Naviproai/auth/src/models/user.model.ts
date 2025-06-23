import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  email?: string;
  password?: string;
  googleId?: string;
  name: string; // Align with schema: name is required
  isEmailVerified?: boolean;
  emailVerificationToken?: string;
  emailVerificationExpires?: Date;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
}

const UserSchema = new Schema<IUser>({
  email: { type: String, unique: true, sparse: true },
  password: { type: String },
  googleId: { type: String, unique: true, sparse: true },
  name: { type: String, required: true },
  isEmailVerified: { type: Boolean, default: false },
  emailVerificationToken: { type: String },
  emailVerificationExpires: { type: Date },
  passwordResetToken: { type: String, select: false },
  passwordResetExpires: { type: Date, select: false },
}, {
  timestamps: true
});

// Fix OverwriteModelError by checking if model exists before defining it
const User = mongoose.models.User || mongoose.model<IUser>('User', UserSchema);

export default User;
