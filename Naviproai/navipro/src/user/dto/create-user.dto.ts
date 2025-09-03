import { AuthProvider } from '../user.schema';

export class CreateUserDto {
  email!: string;
  name!: string;
  password?: string;
  verificationToken?: string | null;
  providers!: AuthProvider[];
  googleId?: string | null;
  isVerified?: boolean;
}
