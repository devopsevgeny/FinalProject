// src/types/auth.ts
export type RoleType =
  | 'GLOBAL_ADMIN'
  | 'SECRET_ADMIN'
  | 'USER_ADMIN'
  | 'CONFIG_ADMIN'
  | 'SECRET_VIEWER'
  | 'CONFIG_VIEWER'
  | 'USER_VIEWER';

export interface User {
  id: string;
  username: string;
  email: string;
  roles: RoleType[];
  lastLogin?: string; // maps from last_login if backend returns it
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
}

export interface LoginCredentials {
  email: string;      // use email (matches your SQL)
  password: string;
}

export interface JWTPayload {
  sub: string;
  email: string;
  roles: RoleType[];
  iat: number;
  exp: number;
}

// what backend returns on /auth/login
export interface LoginResponse {
  access_token: string;
  token_type: string; // "bearer"
  user: {
    id: string;
    username: string;
    email: string;
    roles: RoleType[];
    last_login?: string; // optional
  };
}
