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

## Backend integration

```go
import "github.com/cyphix/goauth"

a, err := goauth.New(goauth.Config{
    DB:                gormDB,        // *gorm.DB — tables are AutoMigrated with an auth_ prefix
    Redis:             redisClient,   // *redis.Client — sessions + throttling
    RPDisplayName:     "My App",
    RPID:              "localhost",   // WebAuthn relying-party ID (domain)
    Origins:           []string{"http://localhost:5173"},
    PublicBaseURL:     "http://localhost:5173", // used for the OIDC redirect URL
    InitAdminUsername: os.Getenv("AUTH_INIT_ADMIN_USERNAME"),
    InitAdminPassword: os.Getenv("AUTH_INIT_ADMIN_PASSWD"),
    DevAutoLogin:      isDev, // NEVER outside development
})

e.Use(a.SessionMiddleware())          // global: session load/save + Origin CSRF check
a.RegisterRoutes(e.Group("/auth"))    // all auth endpoints

api := e.Group("/graphql", a.RequireAuthenticated())
admin := e.Group("/admin", a.RequireRole(goauth.RoleAdmin))

user := goauth.CurrentUser(c)         // in handlers
user := goauth.UserFromContext(ctx)   // in GraphQL resolvers / services
```

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
