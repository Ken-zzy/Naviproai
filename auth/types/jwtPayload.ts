// types/jwtPayload.ts
export interface JwtPayload {
  userId?: string; // For regular auth
  id?: string;     // For Google auth  
  email?: string;
  iat?: number;
  exp?: number;
}
