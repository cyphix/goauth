import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { createContext, useContext } from "react";

import { AuthClient, defaultAuthClient } from "./client.ts";
import type {
  AuthSettings,
  CreateUserInput,
  OidcProviderInput,
  UpdateUserInput,
} from "./types.ts";

export const AuthClientContext = createContext<AuthClient>(defaultAuthClient);

/** Returns the AuthClient from context (defaults to the /auth instance). */
export function useAuthClient(): AuthClient {
  return useContext(AuthClientContext);
}

export const authQueryKeys = {
  config: ["goauth", "config"] as const,
  me: ["goauth", "me"] as const,
  passkeys: ["goauth", "passkeys"] as const,
  users: ["goauth", "admin", "users"] as const,
  oidcProviders: ["goauth", "admin", "oidc"] as const,
  settings: ["goauth", "admin", "settings"] as const,
};

export function useAuthConfig() {
  const client = useAuthClient();
  return useQuery({
    queryKey: authQueryKeys.config,
    queryFn: () => client.getConfig(),
    staleTime: 60_000,
  });
}

export function useMe() {
  const client = useAuthClient();
  return useQuery({
    queryKey: authQueryKeys.me,
    queryFn: () => client.me(),
    staleTime: 60_000,
    retry: false,
  });
}

function useInvalidateSession() {
  const queryClient = useQueryClient();
  return () => {
    queryClient.invalidateQueries({ queryKey: authQueryKeys.me });
    queryClient.invalidateQueries({ queryKey: authQueryKeys.passkeys });
  };
}

export function useLogin() {
  const client = useAuthClient();
  const invalidate = useInvalidateSession();
  return useMutation({
    mutationFn: ({
      username,
      password,
    }: {
      username: string;
      password: string;
    }) => client.login(username, password),
    onSuccess: invalidate,
  });
}

export function useLogout() {
  const client = useAuthClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => client.logout(),
    onSuccess: () => {
      queryClient.setQueryData(authQueryKeys.me, null);
      queryClient.invalidateQueries({ queryKey: authQueryKeys.me });
    },
  });
}

export function usePasskeyLogin() {
  const client = useAuthClient();
  const invalidate = useInvalidateSession();
  return useMutation({
    mutationFn: () => client.passkeyLogin(),
    onSuccess: invalidate,
  });
}

export function usePasskeyRegister() {
  const client = useAuthClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => client.passkeyRegister(name),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: authQueryKeys.passkeys }),
  });
}

export function usePasskeys() {
  const client = useAuthClient();
  return useQuery({
    queryKey: authQueryKeys.passkeys,
    queryFn: () => client.listPasskeys(),
  });
}

export function useDeletePasskey() {
  const client = useAuthClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => client.deletePasskey(id),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: authQueryKeys.passkeys }),
  });
}

export function useChangePassword() {
  const client = useAuthClient();
  return useMutation({
    mutationFn: ({
      currentPassword,
      newPassword,
    }: {
      currentPassword: string;
      newPassword: string;
    }) => client.changePassword(currentPassword, newPassword),
  });
}

// --- Admin hooks ---

export function useAdminUsers() {
  const client = useAuthClient();
  return useQuery({
    queryKey: authQueryKeys.users,
    queryFn: () => client.adminListUsers(),
  });
}

export function useAdminCreateUser() {
  const client = useAuthClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateUserInput) => client.adminCreateUser(input),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: authQueryKeys.users }),
  });
}

export function useAdminUpdateUser() {
  const client = useAuthClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, input }: { id: number; input: UpdateUserInput }) =>
      client.adminUpdateUser(id, input),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: authQueryKeys.users }),
  });
}

export function useAdminDeleteUser() {
  const client = useAuthClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => client.adminDeleteUser(id),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: authQueryKeys.users }),
  });
}

export function useOidcProviders() {
  const client = useAuthClient();
  return useQuery({
    queryKey: authQueryKeys.oidcProviders,
    queryFn: () => client.adminListOidcProviders(),
  });
}

function useInvalidateOidc() {
  const queryClient = useQueryClient();
  return () => {
    queryClient.invalidateQueries({ queryKey: authQueryKeys.oidcProviders });
    queryClient.invalidateQueries({ queryKey: authQueryKeys.settings });
    queryClient.invalidateQueries({ queryKey: authQueryKeys.config });
  };
}

export function useCreateOidcProvider() {
  const client = useAuthClient();
  const invalidate = useInvalidateOidc();
  return useMutation({
    mutationFn: (input: OidcProviderInput) =>
      client.adminCreateOidcProvider(input),
    onSuccess: invalidate,
  });
}

export function useUpdateOidcProvider() {
  const client = useAuthClient();
  const invalidate = useInvalidateOidc();
  return useMutation({
    mutationFn: ({ id, input }: { id: number; input: OidcProviderInput }) =>
      client.adminUpdateOidcProvider(id, input),
    onSuccess: invalidate,
  });
}

export function useDeleteOidcProvider() {
  const client = useAuthClient();
  const invalidate = useInvalidateOidc();
  return useMutation({
    mutationFn: (id: number) => client.adminDeleteOidcProvider(id),
    onSuccess: invalidate,
  });
}

export function useAuthSettings() {
  const client = useAuthClient();
  return useQuery({
    queryKey: authQueryKeys.settings,
    queryFn: () => client.adminGetSettings(),
  });
}

export function useUpdateAuthSettings() {
  const client = useAuthClient();
  const invalidate = useInvalidateOidc();
  return useMutation({
    mutationFn: (settings: AuthSettings) =>
      client.adminUpdateSettings(settings),
    onSuccess: invalidate,
  });
}
