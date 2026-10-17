export { AuthApiError, AuthClient, defaultAuthClient } from "./client.ts";
export { LoginForm, type LoginFormProps } from "./components/LoginForm.tsx";
export {
  OidcSettingsPanel,
  type OidcSettingsPanelProps,
} from "./components/OidcSettingsPanel.tsx";
export {
  PasskeyManager,
  type PasskeyManagerProps,
} from "./components/PasskeyManager.tsx";
export {
  type DeleteUserConfirmRenderProps,
  type ResetPasswordRenderProps,
  UserManagementPanel,
  type UserManagementPanelProps,
} from "./components/UserManagementPanel.tsx";
export {
  requireAuthBeforeLoad,
  requireGuestBeforeLoad,
  type RequireAuthContext,
  type RequireAuthOptions,
  type RequireGuestOptions,
} from "./guard.ts";
export {
  AuthClientContext,
  authQueryKeys,
  useAdminCreateUser,
  useAdminDeleteUser,
  useAdminUpdateUser,
  useAdminUsers,
  useAuthClient,
  useAuthConfig,
  useAuthSettings,
  useChangePassword,
  useCreateOidcProvider,
  useDeleteOidcProvider,
  useDeletePasskey,
  useLogin,
  useLogout,
  useMe,
  useOidcProviders,
  usePasskeyLogin,
  usePasskeyRegister,
  usePasskeys,
  useUpdateAuthSettings,
  useUpdateOidcProvider,
  useUpdateProfile,
} from "./hooks.ts";
export type {
  AuthConfig,
  AuthSettings,
  AuthUser,
  CreateUserInput,
  OidcMode,
  OidcProviderAdmin,
  OidcProviderInput,
  OidcProviderPublic,
  Passkey,
  Role,
  UpdateProfileInput,
  UpdateUserInput,
} from "./types.ts";
