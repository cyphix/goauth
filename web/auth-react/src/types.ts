export type Role = "user" | "admin";

export type OidcMode = "disabled" | "optional" | "required";

export interface AuthUser {
  id: number;
  username: string;
  email: string | null;
  role: Role;
  disabled: boolean;
  hasPassword: boolean;
  passkeyCount: number;
  oidcLinked: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface OidcProviderPublic {
  id: number;
  name: string;
}

export interface AuthConfig {
  passwordLogin: boolean;
  passkeys: boolean;
  oidcMode: OidcMode;
  oidcProviders: OidcProviderPublic[];
  devAutoLogin: boolean;
}

export interface Passkey {
  id: number;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface OidcProviderAdmin {
  id: number;
  name: string;
  issuerUrl: string;
  clientId: string;
  hasClientSecret: boolean;
  scopes: string;
  autoProvision: boolean;
  enabled: boolean;
  createdAt: string;
}

export interface OidcProviderInput {
  name?: string;
  issuerUrl?: string;
  clientId?: string;
  clientSecret?: string;
  scopes?: string;
  autoProvision?: boolean;
  enabled?: boolean;
}

export interface AuthSettings {
  oidcMode: OidcMode;
}

export interface CreateUserInput {
  username: string;
  password?: string;
  email?: string;
  role?: Role;
}

export interface UpdateUserInput {
  username?: string;
  email?: string;
  role?: Role;
  disabled?: boolean;
  password?: string;
}

export interface UpdateProfileInput {
  username?: string;
  email?: string;
}
