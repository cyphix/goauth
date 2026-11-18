# @cyphix/auth-react

React client, TanStack Query hooks and TanStack Router guards for
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

import { useMe, useLogout } from "@cyphix/auth-react";

const { data: me } = useMe();
const logout = useLogout();
```

All requests go to same-origin `/auth/*` with cookies; pass a custom
`AuthClient` through `AuthClientContext` to change the base path.

## Visual UI

This package is headless: it provides no visual components or stylesheet.
Install the shared shadcn UI from the
[cyphix/react-components registry](https://github.com/cyphix/react-components)
in your app instead:

```sh
pnpm dlx shadcn@latest add cyphix/react-components/auth-login-form cyphix/react-components/auth-profile-card cyphix/react-components/auth-passkeys-card cyphix/react-components/auth-users-card
```

The registry also provides `settings-nav`, `settings-layout` and
`auth-admin-guard`. OIDC administration can be built with the retained
`useAuthSettings`, `useUpdateAuthSettings`, `useOidcProviders`,
`useCreateOidcProvider`, `useUpdateOidcProvider` and `useDeleteOidcProvider` hooks.
