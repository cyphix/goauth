import { redirect } from "@tanstack/react-router";

import { AuthClient, defaultAuthClient } from "./client.ts";
import type { AuthUser } from "./types.ts";

export interface RequireAuthOptions {
  client?: AuthClient;
  /** SPA route of the login page. Default "/login". */
  loginPath?: string;
}

export interface RequireAuthContext {
  user: AuthUser;
}

/**
 * TanStack Router `beforeLoad` guard for authenticated layout routes.
 *
 * Resolution order:
 * 1. Existing session -> continue (returns `{ user }` into route context).
 * 2. Dev auto-login (when the backend advertises it) -> silent admin session.
 * 3. Required-OIDC mode -> full-page redirect straight to the provider,
 *    bypassing the login page.
 * 4. Otherwise -> redirect to the login page with `?redirect=` back-link.
 */
export function requireAuthBeforeLoad(options: RequireAuthOptions = {}) {
  const client = options.client ?? defaultAuthClient;
  const loginPath = options.loginPath ?? "/login";

  return async ({
    location,
  }: {
    location: { href: string };
  }): Promise<RequireAuthContext> => {
    const user = await client.me();
    if (user) {
      return { user };
    }

    const config = await client.getConfig();

    if (config.devAutoLogin) {
      try {
        const devUser = await client.devLogin();
        return { user: devUser };
      } catch {
        // fall through to the regular flows
      }
    }

    if (config.oidcMode === "required" && config.oidcProviders.length > 0) {
      const providerId = config.oidcProviders[0]?.id;
      if (providerId !== undefined) {
        window.location.assign(client.oidcStartUrl(providerId, location.href));
        // Halt route resolution while the browser navigates away.
        await new Promise(() => undefined);
      }
    }

    // loginPath is dynamic, so this cannot be statically typed against the
    // consumer's route tree.
    const options = {
      to: loginPath,
      search: { redirect: location.href },
    };
    throw redirect(options as never);
  };
}

export interface RequireGuestOptions {
  client?: AuthClient;
  /** SPA route of the login page — ?redirect= targets under it are rejected (loop guard). Default "/login". */
  loginPath?: string;
  /** Where authenticated users go when ?redirect= is absent or invalid. Default "/". */
  fallbackPath?: string;
  /** Search param carrying the post-login target. Default "redirect". */
  redirectParam?: string;
}

/**
 * TanStack Router `beforeLoad` guard for guest-only routes (the login page).
 *
 * Resolution order:
 * 1. No session -> render the route.
 * 2. Existing session -> redirect to the `?redirect=` search param when it is
 *    a same-site path outside the login page, otherwise to `fallbackPath`.
 *
 * Deliberately does not trigger dev auto-login or OIDC-required redirects:
 * unauthenticated users must be able to reach the login page (e.g. to sign in
 * as a different user after logout).
 */
export function requireGuestBeforeLoad(options: RequireGuestOptions = {}) {
  const client = options.client ?? defaultAuthClient;
  const loginPath = options.loginPath ?? "/login";
  const fallbackPath = options.fallbackPath ?? "/";
  const redirectParam = options.redirectParam ?? "redirect";

  return async ({
    search,
  }: {
    search: Record<string, unknown>;
  }): Promise<void> => {
    const user = await client.me();
    if (!user) {
      return;
    }
    const raw = search[redirectParam];
    const target = typeof raw === "string" ? raw : undefined;
    throw redirect({ to: safeGuestTarget(target, loginPath, fallbackPath) } as never);
  };
}

// safeGuestTarget only allows same-site absolute paths outside the login page
// itself — same rules as the backend's safeNextPath for post-login redirects.
function safeGuestTarget(
  target: string | undefined,
  loginPath: string,
  fallbackPath: string
): string {
  if (
    !target ||
    !target.startsWith("/") ||
    target.startsWith("//") ||
    target === loginPath ||
    target.startsWith(`${loginPath}/`) ||
    target.startsWith(`${loginPath}?`)
  ) {
    return fallbackPath;
  }
  return target;
}
