# goauth

Reusable authentication stack for Echo + React applications:

- **Username + password** login (argon2id) with Redis-backed throttling
- **Passkeys** (WebAuthn, discoverable credentials)
- **OIDC** (e.g. Authentik) — runtime-configurable from the admin API, either as
  an extra button on the login page (`optional`) or as the required, exclusive
  method that bypasses local login entirely (`required`)
- **Server-side sessions** via SCS + Redis (cookie, `SameSite=Lax`, Origin CSRF check)
- **Admin API** for user management, OIDC providers and mode switching
- **Init admin bootstrap** — first admin created from config when the users table is empty
- **Dev auto-login** — opt-in, dev-only endpoint for frictionless manual testing

The companion React package lives in [`web/auth-react`](web/auth-react).

## Dependencies

Besides Echo, GORM and go-redis, the module uses SCS's official
`github.com/alexedwards/scs/goredisstore` session store and one sibling module:

- **[`github.com/cyphix/gologg`](https://github.com/cyphix/gologg)** —
  zerolog-based structured logging. goauth obtains its logger via
  `logg.Ctx("goauth", "core")`, so log output automatically matches any host
  application that also logs through gologg (level, format and writer are
  configured once by the host).

Session keys use the `goauth:session:` prefix via
`goredisstore.NewWithPrefix`. Hosts provide raw `*gorm.DB` and `*redis.Client`
handles; goauth does not open their connections.

> **Note:** `go.mod` resolves gologg through `replace` to a sibling checkout
> (`../gologg`). To use goauth standalone, check out these two repositories
> side by side, or remove that replacement and use the required tagged version.

## Backend integration (Echo)

goauth is handed ready-made database handles — it never opens connections
itself. Everything below assumes an existing Echo app.

**1. Provide the handles.** A `*gorm.DB` (Postgres, SQLite, … — auth tables
are AutoMigrated with an `auth_` prefix on `New`) and a `*redis.Client`
(sessions + login throttling).

**2. Assemble the module.**

```go
import "github.com/cyphix/goauth"

a, err := goauth.New(goauth.Config{
    DB:                gormDB,        // *gorm.DB — tables are AutoMigrated with an auth_ prefix
    Redis:             redisClient,   // *redis.Client — sessions + throttling
    RPDisplayName:     "My App",
    RPID:              "localhost",   // WebAuthn relying-party ID (domain); empty disables passkeys
    Origins:           []string{"http://localhost:5173"},  // browser origins: WebAuthn + Origin CSRF check
    PublicBaseURL:     "http://localhost:5173", // used for the OIDC redirect URL
    CookieSecure:      false,         // true behind HTTPS
    ClientIP:          nil,           // defaults to TCP peer; configure trusted proxy extraction if needed
    InitAdminUsername: os.Getenv("AUTH_INIT_ADMIN_USERNAME"),
    InitAdminPassword: os.Getenv("AUTH_INIT_ADMIN_PASSWD"),
    DevAutoLogin:      isDev, // NEVER outside development
})
if err != nil {
    log.Fatal(err)
}
```

Login throttling defaults to the TCP peer address, ignoring forwarded headers. If
the app runs behind a reverse proxy, configure a trusted extractor such as
`echo.ExtractIPFromXFFHeader(echo.TrustIPRange(...))`; otherwise all clients share
the proxy's per-IP bucket and can lock each other out. The limits are 10 attempts
per account and client IP, 30 per account across all IPs, and 100 per client IP
across all accounts, each within five minutes.

**3. Mount it on Echo.** The session middleware must be global (it also
performs the Origin CSRF check); routes mount under a group of your choice
(`/auth` is what the React package expects by default):

```go
e := echo.New()

e.Use(a.SessionMiddleware())          // global: session load/save + Origin CSRF check
a.RegisterRoutes(e.Group("/auth"))    // all auth endpoints

// Protect your own routes with the provided guards:
api := e.Group("/api", a.RequireAuthenticated())
admin := e.Group("/admin", a.RequireRole(goauth.RoleAdmin))
```

**4. Read the current user** where you need it:

```go
user := goauth.CurrentUser(c)         // in Echo handlers
user := goauth.UserFromContext(ctx)   // in services / GraphQL resolvers
```

The init admin is created on startup when the users table is empty. On the
frontend, use [`@cyphix/auth-react`](web/auth-react) for the client, hooks and
route guards, or call the endpoints below directly. Install the visual auth UI
from the [cyphix/react-components registry](https://github.com/cyphix/react-components)
(`auth-login-form`, `auth-profile-card`, `auth-passkeys-card`, `auth-users-card`).

## Avatars

Avatar routes are opt-in and independent of `RegisterRoutes`. Choose your app's
paths and apply session/authentication and admin-role middleware on the groups:

```go
me := e.Group("/api/me/avatar", a.SessionMiddleware(), a.RequireAuthenticated())
admin := e.Group("/api/admin", a.SessionMiddleware(), a.RequireRole(goauth.RoleAdmin))
a.RegisterAvatarRoutes(me, admin)
```

This mounts PUT/GET/DELETE `/api/me/avatar` and GET
`/api/admin/users/:id/avatar`. For example, Worldbuilder can use `/admin` as the
admin prefix instead. For custom routing, mount `a.UploadAvatar`, `a.Avatar`,
`a.DeleteAvatar` and `a.UserAvatar` individually with the same middleware.

PUT accepts multipart field `file`. `Config.MaxAvatarBytes` limits the entire
request (including multipart overhead), defaulting to 8 MiB. Nonempty uploads
must sniff as `image/*`; bytes are stored as-is, without decoding or resizing.
Upload replaces any existing avatar. Upload/delete return 204 and bump the
user's `updated_at` for frontend cache busting. GET returns the stored content
type and `Cache-Control: private, max-age=0, must-revalidate`, or 204 when absent.

`UserAvatar` stores bytes in `auth_user_avatars`, keyed by `user_id` with a foreign
key to `auth_users(id)` and `ON DELETE CASCADE` (physical user deletion).
Applications managing their own migrations **must keep those migrations
identical to goauth's models**, including `auth_user_avatars`; goauth also adds
the table through AutoMigrate. SQLite connections must enable foreign-key
enforcement for cascading deletes (for example, `_foreign_keys=on`).

## Endpoints (mounted at `/auth` by default)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/config` | — | Login methods, OIDC mode/providers, dev auto-login flag |
| POST | `/login` | — | Username + password |
| POST | `/logout` | session | Destroy session |
| GET | `/me` | session | Current user |
| POST | `/password` | session | Change own password |
| POST | `/passkey/login/begin,finish` | — | Discoverable passkey login |
| POST | `/passkey/register/begin,finish` | session | Register a passkey |
| GET/DELETE | `/passkeys`, `/passkeys/:id` | session | Manage own passkeys |
| GET | `/oidc/:id/start` | — | Begin OIDC code flow (PKCE) |
| GET | `/oidc/callback` | — | OIDC redirect URI |
| GET/POST/PATCH/DELETE | `/admin/users…` | admin | User CRUD, role, disable, password reset |
| GET/POST/PATCH/DELETE | `/admin/oidc…` | admin | OIDC provider CRUD |
| GET/PUT | `/admin/settings` | admin | OIDC mode (`disabled` / `optional` / `required`) |
| POST | `/dev/login` | — | Dev-only session as the init admin (flag-gated) |

## OIDC modes

- `disabled` — local login only.
- `optional` — local login stays fully usable; enabled providers are listed as
  buttons below the passkey button on the login page.
- `required` — visiting the app unauthenticated goes straight to the provider;
  password/passkey endpoints are rejected. Switch back by an admin session
  (`PUT /auth/admin/settings`) or by clearing the `auth_settings` row.

Provider changes apply at runtime — discovery documents are cached per row
revision and invalidated on admin edits.

## Tests

```bash
go test ./...
```

The suite uses in-memory SQLite + miniredis, a mock OIDC provider and a
software WebAuthn authenticator — no external services required.

## Secret scanning

BetterLeaks gates pushes and PRs (`.github/workflows/betterleaks.yml`); the
repo config lives in [`.betterleaks.toml`](.betterleaks.toml). Enable the local
pre-push scan once per clone:

```bash
./scripts/install-git-hooks.sh   # sets core.hooksPath; requires Docker or the betterleaks CLI
scripts/betterleaks-scan.sh      # manual scan of unpushed commits
```
