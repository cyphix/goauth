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
