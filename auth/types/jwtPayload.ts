// types/jwtPayload.ts
export interface JwtPayload {
  userId?: string; // Represents the user's unique identifier
  email?: string;
  iat?: number;
  exp?: number;
}
