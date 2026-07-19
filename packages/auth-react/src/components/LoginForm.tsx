import { type FormEvent, useEffect, useMemo, useState } from "react";

import { useAuthClient, useAuthConfig, useLogin, usePasskeyLogin } from "../hooks.ts";
import type { AuthUser } from "../types.ts";

const OIDC_ERROR_MESSAGES: Record<string, string> = {
  provider_unavailable: "The identity provider is unreachable. Check the provider configuration.",
  provider_error: "The identity provider rejected the login.",
  no_pending_login: "The login attempt expired. Please try again.",
  state_mismatch: "The login attempt could not be verified. Please try again.",
  exchange_failed: "The identity provider rejected the login exchange.",
  missing_id_token: "The identity provider response was incomplete.",
  invalid_id_token: "The identity provider token could not be verified.",
  nonce_mismatch: "The login attempt could not be verified. Please try again.",
  invalid_claims: "The identity provider response was invalid.",
  missing_subject: "The identity provider response was missing a subject.",
  not_provisioned: "This account has not been provisioned. Contact an administrator.",
  account_disabled: "This account is disabled.",
};

export interface LoginFormProps {
  /** Called after any successful login (password or passkey). */
  onSuccess?: (user: AuthUser) => void;
  /** Path the OIDC flow should land on after login. Default "/". */
  next?: string;
  className?: string;
}

/**
 * Complete login page body driven by GET /auth/config:
 * - username/password form (when local login is allowed)
 * - passkey button beneath it
 * - OIDC provider buttons beneath the passkey button (optional mode)
 * - in required mode it immediately redirects to the provider instead of
 *   rendering, unless an OIDC error code is present in the URL.
 */
export function LoginForm({ onSuccess, next = "/", className }: LoginFormProps) {
  const client = useAuthClient();
  const { data: config, isLoading } = useAuthConfig();
  const login = useLogin();
  const passkeyLogin = usePasskeyLogin();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const oidcError = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("error");
    if (!code) {
      return null;
    }
    return OIDC_ERROR_MESSAGES[code] ?? `Login failed (${code}).`;
  }, []);

  const exclusive = config?.oidcMode === "required";
  const firstProvider = config?.oidcProviders[0];

  // Exclusive mode: bypass the local login page entirely.
  useEffect(() => {
    if (exclusive && firstProvider && !oidcError) {
      window.location.assign(client.oidcStartUrl(firstProvider.id, next));
    }
  }, [exclusive, firstProvider, oidcError, client, next]);

  if (isLoading || !config) {
    return <div className={cx("goauth-login", className)} />;
  }

  if (exclusive && !oidcError) {
    return (
      <div className={cx("goauth-login", className)}>
        <p className="goauth-muted">Redirecting to {firstProvider?.name ?? "your identity provider"}…</p>
      </div>
    );
  }

  const handlePasswordLogin = (event: FormEvent) => {
    event.preventDefault();
    login.mutate(
      { username, password },
      { onSuccess: (user) => onSuccess?.(user) }
    );
  };

  const handlePasskeyLogin = () => {
    passkeyLogin.mutate(undefined, {
      onSuccess: (user) => onSuccess?.(user),
    });
  };

  const mutationError = login.error ?? passkeyLogin.error;

  return (
    <div className={cx("goauth-login", className)}>
      {oidcError ? <div className="goauth-error">{oidcError}</div> : null}

      {config.passwordLogin ? (
        <form className="goauth-login-form" onSubmit={handlePasswordLogin}>
          <label className="goauth-field">
            <span>Username</span>
            <input
              autoCapitalize="none"
              autoComplete="username"
              autoCorrect="off"
              name="username"
              onChange={(e) => setUsername(e.target.value)}
              required
              value={username}
            />
          </label>
          <label className="goauth-field">
            <span>Password</span>
            <input
              autoComplete="current-password"
              name="password"
              onChange={(e) => setPassword(e.target.value)}
              required
              type="password"
              value={password}
            />
          </label>
          <button
            className="goauth-button goauth-button-primary"
            disabled={login.isPending}
            type="submit"
          >
            {login.isPending ? "Signing in…" : "Sign in"}
          </button>
        </form>
      ) : null}

      {config.passkeys ? (
        <button
          className="goauth-button goauth-button-passkey"
          disabled={passkeyLogin.isPending}
          onClick={handlePasskeyLogin}
          type="button"
        >
          {passkeyLogin.isPending ? "Waiting for passkey…" : "Sign in with a passkey"}
        </button>
      ) : null}

      {config.oidcMode !== "disabled" &&
        config.oidcProviders.map((provider) => (
          <a
            className="goauth-button goauth-button-oidc"
            href={client.oidcStartUrl(provider.id, next)}
            key={provider.id}
          >
            Sign in with {provider.name}
          </a>
        ))}

      {mutationError ? (
        <div className="goauth-error">{mutationError.message}</div>
      ) : null}

      {exclusive && oidcError && firstProvider ? (
        <a
          className="goauth-button goauth-button-oidc"
          href={client.oidcStartUrl(firstProvider.id, next)}
        >
          Retry sign in with {firstProvider.name}
        </a>
      ) : null}
    </div>
  );
}

function cx(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
