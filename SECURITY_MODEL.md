# Threat model: cyphix Go libraries (goauth, gologg, godatabases)

## System overview
Three Go libraries. Five apps vendor them as git submodules under `pkg/`, wired up through `replace` directives: **homelab, crm, mystica, healtho, worldbuilder**. Each app is a single Echo binary in a distroless container, and each runs next to Postgres and Redis (see each app's `compose.yml` or `docker-compose.yml`).
- **goauth** is the authentication stack. It is the only library with a network surface. It serves username/password login (argon2id), WebAuthn passkeys, runtime-configurable OIDC (PKCE, state, nonce), server-side SCS sessions stored in Redis, an admin API, and the `@cyphix/auth-react` client package.
- **godatabases** wraps GORM for SQLite and Postgres (`sql/`) and go-redis (`redis/`). It also provides the SCS Redis session store (`redis/redisstore.go`) that goauth uses with the prefix `goauth:session:`.
- **gologg** is a thread-safe zerolog wrapper (`logg.go`). goauth and godatabases log through it, and so do the host apps.

**Deployment** (user-confirmed): mixed. Some host apps are public on the internet over HTTPS and some are LAN-only. The consuming apps serve as deployment references, and no separate infrastructure repository exists. The compose files default `AUTH_COOKIE_SECURE=true`, require `AUTH_ORIGINS`, `AUTH_RPID` and `AUTH_PUBLIC_BASE_URL`, and default `REDIS_PASSWORD` to empty. Redis and Postgres sit on the compose network. Every app gates `DevAutoLogin` on `SERVER_ENV=development`.

## Trust boundaries
1. Browser ↔ host app: everything under `/auth/*` (goauth `RegisterRoutes`) plus the host's routes protected by `RequireAuthenticated` / `RequireRole`.
2. Host app ↔ OIDC provider: discovery, the token exchange, and ID-token verification (`oidc.go`). The provider is **not fully trusted** (user-confirmed).
3. Host app ↔ Redis / Postgres: session blobs, throttle counters, user rows, passkey credentials, and OIDC client secrets. A **same-network attacker** is in scope (user-confirmed).
4. Non-admin user ↔ admin: `RequireRole(RoleAdmin)` on `/auth/admin/*` and on the host's admin routes.

## Components
| Component | Code |
|---|---|
| **goauth Sessions** | `goauth/session.go` (SessionMiddleware, Origin CSRF check, RequireAuthenticated/RequireRole, createSession), `goauth/goauth.go` (Config, cookie settings, init-admin bootstrap), `goauth/models.go`, `goauth/errors.go` |
| **goauth Local Login** | `goauth/handlers.go` (login, logout, me, profile, password, dev login), `goauth/users.go` (argon2id, user CRUD and validation), `goauth/throttle.go` |
| **goauth Passkeys** | `goauth/passkey.go` |
| **goauth OIDC** | `goauth/oidc.go` |
| **goauth Admin API** | `goauth/admin.go` |
| **auth-react Client** | `goauth/web/auth-react/**` (client.ts, guard.ts, hooks.ts, components) |
| **godatabases** | `godatabases/sql/**`, `godatabases/redis/**` (including the session store `redisstore.go`) |
| **gologg** | `gologg/logg.go` |

## Entry points and who can reach them
- Unauthenticated: `GET /auth/config`, `POST /auth/login`, `POST /auth/passkey/login/{begin,finish}`, `GET /auth/oidc/:id/start`, `GET /auth/oidc/callback`, `GET /auth/me`, `POST /auth/logout`.
- Authenticated users: `PATCH /auth/me`, `POST /auth/password`, passkey registration, list and delete.
- Admins: `/auth/admin/users*`, `/auth/admin/oidc*`, `/auth/admin/settings`.
- Dev only: `POST /auth/dev/login`, registered only when `Config.DevAutoLogin` is set.
- gologg and godatabases have no network entry points. Their inputs come from host configuration and from the data passed through them.

## Assets
- Session tokens, the cookie, and the Redis session data. Holding a session means full account takeover, including admin.
- User accounts and roles: privilege escalation to `admin` gives control of every user and of the OIDC configuration.
- Password hashes (argon2id) and WebAuthn credentials (`auth_webauthn_credentials`).
- OIDC client secrets (`auth_oidc_providers.client_secret`, stored in plaintext in the database; the API exposes only `hasClientSecret`).
- Secrets in configuration: Postgres DSNs, Redis passwords, and the init-admin password. These must not leak into logs.
- Data in the host apps (CRM contacts, health data, homelab inventory, and so on), reachable through any auth bypass.

## Attackers (user-confirmed)
1. **Unauthenticated remote attacker** on the internet (public deployments) or on the LAN. Goals: auth bypass, credential stuffing or brute force, session fixation, open redirect, CSRF.
2. **Authenticated non-admin user** escalating to admin, or reaching other users' passkeys, sessions or profiles (IDOR).
3. **Malicious or compromised OIDC provider**: forged or confused claims, account linking or takeover through `sub`/email, auto-provisioning abuse, SSRF through discovery.
4. **Same-network attacker**: MITM on Redis or Postgres traffic (no TLS by default), direct access to an unauthenticated Redis, tampering with session blobs.

Admins are trusted to run the admin API. They were not listed as an attacker.

## Existing controls
- Origin-header CSRF check on unsafe methods (`session.go` `originCheckMiddleware`): `Origin: null` is rejected; a missing Origin falls back to `Sec-Fetch-Site` (`same-origin`/`none`) or an allowed `Referer`, and passes when neither is present. Login also requires `application/json`. The session cookie is `HttpOnly` and `SameSite=Lax`.
- The session token is renewed on login (`createSession` → `RenewToken`), and logout destroys the session.
- Disabled users are rejected on every session load. The last active admin cannot be disabled or demoted (`isLastActiveAdmin`).
- Login throttle: 10 attempts per 5 minutes, keyed by `username:RealIP`, in Redis. Its accuracy depends on how the host app's Echo `IPExtractor` reads proxy headers.
- OIDC: state, nonce and PKCE S256 checks, ID-token verification bound to the ClientID, `email_verified` required before an email is adopted, and `safeNextPath` blocks `//` and absolute URLs. Auto-provisioning is off unless enabled per provider.
- Passkeys: discoverable login, the clone-warning check, and user-scoped credential deletion.
- Secret scanning: BetterLeaks runs in CI and as a pre-push hook in goauth.

## Out of scope / accepted risk (user-confirmed)
- **Test files and test helpers** (`*_test.go`, `testdata/`). They are also excluded from the scan.
- **Host-app misconfiguration**: `CookieSecure=false`, wrong or overly broad `Origins`, and a missing `PublicBaseURL` are the host app's responsibility.
- **Dev-only features**: `DevAutoLogin` and `POST /auth/dev/login`, unless they can be reached without the host setting the flag.

## Open questions
- Is the Redis instance always on a private network, and is `REDIS_PASSWORD` set in the public deployments?
- Do the public deployments run behind a reverse proxy, and is Echo's `IPExtractor` configured for it? This decides whether the login throttle can be bypassed with a spoofed `X-Forwarded-For`.
- Is OIDC auto-provisioning enabled in any deployment?
