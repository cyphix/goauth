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

Besides Echo, GORM and go-redis, the module builds on two sibling `cyphix`
modules:

- **[`github.com/cyphix/gologg`](https://github.com/cyphix/gologg)** —
  zerolog-based structured logging. goauth obtains its logger via
  `logg.Ctx("goauth", "core")`, so log output automatically matches any host
  application that also logs through gologg (level, format and writer are
  configured once by the host).
- **[`github.com/cyphix/godatabases`](https://github.com/cyphix/godatabases)** —
  database helpers. goauth uses `godatabases/redis` for the SCS session store
  (`NewRedisStoreWithPrefix(client, "goauth:session:")`), which keeps all
  session keys namespaced in Redis. The host app is free to build its
  `*gorm.DB` / `*redis.Client` with godatabases too (that is what worldbuilder
  does), but goauth only requires the raw handles.

> **Note:** `go.mod` currently resolves both modules via
> `replace` directives to sibling checkouts (`../gologg`, `../godatabases`).
> This matches how the module is consumed as a git submodule next to its
> siblings (e.g. under `pkg/` in a monorepo). To use goauth standalone, check
> out all three repos side by side, or drop the `replace` lines and depend on
> tagged versions.

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
    InitAdminUsername: os.Getenv("AUTH_INIT_ADMIN_USERNAME"),
    InitAdminPassword: os.Getenv("AUTH_INIT_ADMIN_PASSWD"),
    DevAutoLogin:      isDev, // NEVER outside development
})
if err != nil {
    log.Fatal(err)
}
```

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
frontend, pair this with [`@cyphix/auth-react`](web/auth-react) (`LoginForm`,
`requireAuthBeforeLoad`, admin panels), or call the endpoints below directly.

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
