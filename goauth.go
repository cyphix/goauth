// Package goauth is a reusable, embeddable authentication stack for Echo
// applications. It provides username+password login, passkeys (WebAuthn) and
// runtime-configurable OIDC, backed by server-side sessions (SCS + Redis) and
// GORM-managed tables.
//
// Integration surface:
//
//	a, err := goauth.New(goauth.Config{DB: gormDB, Redis: redisClient, ...})
//	e.Use(a.SessionMiddleware())
//	a.RegisterRoutes(e.Group("/auth"))
//	api := e.Group("/graphql", a.RequireAuthenticated())
package goauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	redisstore "github.com/cyphix/godatabases/redis"
	logg "github.com/cyphix/gologg"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

const (
	// DefaultCookieName is used when Config.CookieName is empty.
	DefaultCookieName = "goauth_session"
	// DefaultSessionLifetime is used when Config.SessionLifetime is zero.
	DefaultSessionLifetime = 7 * 24 * time.Hour
	// DefaultMountPath is used when Config.MountPath is empty. It must match
	// the Echo group prefix passed to RegisterRoutes.
	DefaultMountPath = "/auth"
)

// Config configures a goauth instance. DB and Redis are required; everything
// else has sensible defaults.
type Config struct {
	// DB is the GORM database handle the module stores its tables in. All
	// tables are prefixed with "auth_".
	DB *gorm.DB
	// Redis backs sessions and login throttling.
	Redis *redis.Client

	// RPDisplayName / RPID / Origins configure WebAuthn (passkeys). When RPID
	// is empty, passkey endpoints are disabled.
	RPDisplayName string
	RPID          string
	// Origins are the browser origins allowed for WebAuthn ceremonies and the
	// Origin-header CSRF check (e.g. http://localhost:5173).
	Origins []string

	// PublicBaseURL is the externally reachable base URL of the app (no
	// trailing slash), used to build the OIDC redirect URL. Example:
	// "http://localhost:5173". Required for OIDC logins.
	PublicBaseURL string
	// MountPath is the route prefix RegisterRoutes is mounted at. Defaults to
	// "/auth". Only used to build the OIDC callback URL.
	MountPath string

	CookieName string
	// CookieSecure marks the session cookie Secure (HTTPS-only deployments).
	CookieSecure    bool
	SessionLifetime time.Duration

	// InitAdminUsername / InitAdminPassword bootstrap the very first admin
	// account: when the users table is empty at startup, this admin is
	// created. No-op once any user exists.
	InitAdminUsername string
	InitAdminPassword string

	// DevAutoLogin registers POST {mount}/dev/login which creates a session
	// as the init admin without credentials, and advertises the capability in
	// GET {mount}/config. NEVER enable outside development builds.
	DevAutoLogin bool
}

// Auth is the assembled authentication module.
type Auth struct {
	cfg      Config
	db       *gorm.DB
	redis    *redis.Client
	sessions *scs.SessionManager
	webauthn *webauthn.WebAuthn
	oidc     *oidcRuntime
	logger   zerolog.Logger
}

// New validates the config, migrates the auth tables, bootstraps the init
// admin and returns a ready-to-mount Auth.
func New(cfg Config) (*Auth, error) {
	if cfg.DB == nil {
		return nil, errors.New("goauth: Config.DB is required")
	}
	if cfg.Redis == nil {
		return nil, errors.New("goauth: Config.Redis is required")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultCookieName
	}
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = DefaultSessionLifetime
	}
	if cfg.MountPath == "" {
		cfg.MountPath = DefaultMountPath
	}
	cfg.MountPath = "/" + strings.Trim(cfg.MountPath, "/")
	cfg.PublicBaseURL = strings.TrimRight(cfg.PublicBaseURL, "/")
	cfg.InitAdminUsername = NormalizeUsername(cfg.InitAdminUsername)

	a := &Auth{
		cfg:    cfg,
		db:     cfg.DB,
		redis:  cfg.Redis,
		logger: logg.Ctx("goauth", "core"),
	}

	if err := a.db.AutoMigrate(&User{}, &WebauthnCredential{}, &OIDCProvider{}, &Settings{}); err != nil {
		return nil, fmt.Errorf("goauth: migrate tables: %w", err)
	}

	sm := scs.New()
	sm.Store = redisstore.NewRedisStoreWithPrefix(cfg.Redis, "goauth:session:")
	sm.Lifetime = cfg.SessionLifetime
	sm.Cookie.Name = cfg.CookieName
	sm.Cookie.HttpOnly = true
	sm.Cookie.Secure = cfg.CookieSecure
	sm.Cookie.SameSite = sameSiteLax()
	sm.Cookie.Path = "/"
	a.sessions = sm

	if cfg.RPID != "" {
		wa, err := webauthn.New(&webauthn.Config{
			RPDisplayName: defaultString(cfg.RPDisplayName, cfg.RPID),
			RPID:          cfg.RPID,
			RPOrigins:     cfg.Origins,
		})
		if err != nil {
			return nil, fmt.Errorf("goauth: webauthn config: %w", err)
		}
		a.webauthn = wa
	}

	a.oidc = newOIDCRuntime(a)

	if err := a.ensureSettings(); err != nil {
		return nil, fmt.Errorf("goauth: ensure settings: %w", err)
	}
	if err := a.bootstrapInitAdmin(); err != nil {
		return nil, fmt.Errorf("goauth: bootstrap init admin: %w", err)
	}

	return a, nil
}

// DB exposes the underlying GORM handle (mainly for tests and seeds).
func (a *Auth) DB() *gorm.DB { return a.db }

// PasskeysEnabled reports whether WebAuthn is configured.
func (a *Auth) PasskeysEnabled() bool { return a.webauthn != nil }

// bootstrapInitAdmin creates the initial admin account when no users exist.
func (a *Auth) bootstrapInitAdmin() error {
	if a.cfg.InitAdminUsername == "" || a.cfg.InitAdminPassword == "" {
		return nil
	}
	var count int64
	if err := a.db.Model(&User{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	user, err := a.CreateUser(a.cfg.InitAdminUsername, a.cfg.InitAdminPassword, "", RoleAdmin)
	if err != nil {
		return err
	}
	a.logger.Info().Str("username", user.Username).Msg("created init admin user")
	return nil
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
