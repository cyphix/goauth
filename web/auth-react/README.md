# @cyphix/auth-react

React client, TanStack Query hooks, components and a TanStack Router guard for
the [goauth](../..) backend. Ships as TypeScript source — bundle it with your
app (Vite handles this out of the box).

## Install

```jsonc
// package.json (repo consumes goauth as a submodule at pkg/goauth)
"dependencies": {
  "@cyphix/auth-react": "file:../pkg/goauth/web/auth-react"
}
```

Peer dependencies: `react`, `@tanstack/react-query`, `@tanstack/react-router`.

## Usage

```tsx
import "@cyphix/auth-react/styles.css"; // optional default styling

// Login page: renders per GET /auth/config — password form, passkey button
// beneath it, OIDC buttons beneath that; in required mode it redirects
// straight to the provider.
import { LoginForm } from "@cyphix/auth-react";
<LoginForm onSuccess={() => navigate({ to: "/" })} />;

// Route guard for an authenticated layout route (handles dev auto-login and
// required-OIDC bypass):
import { requireAuthBeforeLoad } from "@cyphix/auth-react";
export const Route = createFileRoute("/_app")({
  beforeLoad: requireAuthBeforeLoad({ loginPath: "/login" }),
  component: Layout,
});
```

Both guards (`requireAuthBeforeLoad` / `requireGuestBeforeLoad`) resolve the
session through the TanStack Query cache (`authQueryKeys.me`, 60 s staleTime)
when a `QueryClient` is passed via the `queryClient` option or is present in
the router context (e.g. `createRootRouteWithContext<{ queryClient: QueryClient }>()`).
Otherwise each call fetches `/me` fresh. Trade-off: with caching, a
server-side session expiry is noticed by the guard up to 60 s late (API 401s
still enforce it immediately).

```tsx

// Session hooks:
const { data: me } = useMe();
const logout = useLogout();

// Admin pages:
<UserManagementPanel />
<OidcSettingsPanel />

// Profile page:
<PasskeyManager />
```

All requests go to same-origin `/auth/*` with cookies; pass a custom
`AuthClient` through `AuthClientContext` to change the base path.
