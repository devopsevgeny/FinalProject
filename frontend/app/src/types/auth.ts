export type RoleType = 
  | 'GLOBAL_ADMIN'
  | 'USER_VIEWER';

export interface User {
  id: string;
  username: string;
  email: string;
  roles: RoleType[];
  lastLogin?: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface JWTPayload {
  sub: string;
  email: string;
  roles: RoleType[];
  iat: number;
  exp: number;
}