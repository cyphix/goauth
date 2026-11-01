package goauth

import (
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

// UserDTO is the JSON shape of a user returned by the API.
type UserDTO struct {
	ID           uint      `json:"id"`
	Username     string    `json:"username"`
	Email        *string   `json:"email"`
	Role         Role      `json:"role"`
	Disabled     bool      `json:"disabled"`
	HasPassword  bool      `json:"hasPassword"`
	PasskeyCount int       `json:"passkeyCount"`
	OIDCLinked   bool      `json:"oidcLinked"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

func toUserDTO(u *User) UserDTO {
	return UserDTO{
		ID:           u.ID,
		Username:     u.Username,
		Email:        u.Email,
		Role:         u.Role,
		Disabled:     u.Disabled,
		HasPassword:  u.HasPassword(),
		PasskeyCount: len(u.Credentials),
		OIDCLinked:   u.OIDCSub != nil,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}

type oidcProviderPublicDTO struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

type authConfigDTO struct {
	PasswordLogin bool                    `json:"passwordLogin"`
	Passkeys      bool                    `json:"passkeys"`
	OIDCMode      OIDCMode                `json:"oidcMode"`
	OIDCProviders []oidcProviderPublicDTO `json:"oidcProviders"`
	DevAutoLogin  bool                    `json:"devAutoLogin"`
}

// RegisterRoutes mounts every goauth endpoint on the group. The group's
// prefix must match Config.MountPath (default "/auth"). SessionMiddleware
// must already be applied (globally or on the group).
func (a *Auth) RegisterRoutes(g *echo.Group) {
	g.GET("/config", a.handleConfig)
	g.POST("/login", a.handleLogin)
	g.POST("/logout", a.handleLogout)
	g.GET("/me", a.handleMe)

	authed := g.Group("", a.RequireAuthenticated())
	authed.PATCH("/me", a.handleUpdateProfile)
	authed.POST("/password", a.handleChangePassword)

	a.registerPasskeyRoutes(g, authed)
	a.registerOIDCRoutes(g)

	admin := g.Group("/admin", a.RequireRole(RoleAdmin))
	a.registerAdminRoutes(admin)

	if a.cfg.DevAutoLogin {
		g.POST("/dev/login", a.handleDevLogin)
	}
}

func (a *Auth) handleConfig(c echo.Context) error {
	settings, err := a.GetSettings()
	if err != nil {
		return err
	}
	cfg := authConfigDTO{
		PasswordLogin: settings.OIDCMode != OIDCModeRequired,
		Passkeys:      a.PasskeysEnabled() && settings.OIDCMode != OIDCModeRequired,
		OIDCMode:      settings.OIDCMode,
		OIDCProviders: []oidcProviderPublicDTO{},
		DevAutoLogin:  a.cfg.DevAutoLogin,
	}
	if settings.OIDCMode != OIDCModeDisabled {
		providers, err := a.ListOIDCProviders(true)
		if err != nil {
			return err
		}
		for _, p := range providers {
			cfg.OIDCProviders = append(cfg.OIDCProviders, oidcProviderPublicDTO{ID: p.ID, Name: p.Name})
		}
	}
	return c.JSON(http.StatusOK, cfg)
}

type loginRequest struct {
	// Identifier is the login identifier: username or email. Username is
	// accepted for backwards compatibility.
	Identifier string `json:"identifier"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

func (r *loginRequest) id() string {
	if r.Identifier != "" {
		return r.Identifier
	}
	return r.Username
}

func (a *Auth) handleLogin(c echo.Context) error {
	mediaType, _, err := mime.ParseMediaType(c.Request().Header.Get(echo.HeaderContentType))
	if err != nil || mediaType != "application/json" {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "content type must be application/json")
	}
	if err := a.rejectWhenOIDCRequired(); err != nil {
		return err
	}
	var req loginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.id() == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "username and password are required")
	}

	throttleKey := NormalizeUsername(req.id()) + ":" + c.RealIP()
	allowed, err := a.throttleAllow(c.Request().Context(), throttleKey)
	if err != nil {
		return err
	}
	if !allowed {
		return echo.NewHTTPError(http.StatusTooManyRequests, "too many login attempts, try again later")
	}

	user, err := a.Authenticate(req.id(), req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid username or password")
		}
		return err
	}
	a.throttleReset(c.Request().Context(), throttleKey)

	if err := a.createSession(c, user); err != nil {
		return err
	}
	a.attachUser(c, user)
	return c.JSON(http.StatusOK, toUserDTO(user))
}

func (a *Auth) handleLogout(c echo.Context) error {
	if err := a.destroySession(c); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func (a *Auth) handleMe(c echo.Context) error {
	user, err := a.loadSessionUser(c)
	if err != nil {
		return err
	}
	if user == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	if err := a.db.Preload("Credentials").First(user, user.ID).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusOK, toUserDTO(user))
}

type updateProfileRequest struct {
	Username *string `json:"username"`
	Email    *string `json:"email"`
}

// handleUpdateProfile applies a self-service username/email change.
func (a *Auth) handleUpdateProfile(c echo.Context) error {
	user := CurrentUser(c)
	var req updateProfileRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Username == nil && req.Email == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "nothing to update")
	}
	updated, err := a.UpdateProfile(user.ID, ProfilePatch{Username: req.Username, Email: req.Email})
	if err != nil {
		return mapServiceError(err)
	}
	a.attachUser(c, updated)
	return c.JSON(http.StatusOK, toUserDTO(updated))
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (a *Auth) handleChangePassword(c echo.Context) error {
	user := CurrentUser(c)
	var req changePasswordRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if err := a.changePassword(user, req.CurrentPassword, req.NewPassword); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return echo.NewHTTPError(http.StatusUnauthorized, "current password is incorrect")
		}
		if errors.Is(err, ErrPasswordManagedByIdP) {
			return echo.NewHTTPError(http.StatusForbidden, "this account signs in through an identity provider; ask an administrator to set a local password")
		}
		return mapServiceError(err)
	}
	renewed := *user
	renewed.SessionVersion++
	if err := a.createSession(c, &renewed); err != nil {
		return err
	}
	a.attachUser(c, &renewed)
	return c.NoContent(http.StatusNoContent)
}

// handleDevLogin creates a session as the init admin without credentials.
// Only registered when Config.DevAutoLogin is true.
func (a *Auth) handleDevLogin(c echo.Context) error {
	username := a.cfg.InitAdminUsername
	var user *User
	var err error
	if username != "" {
		user, err = a.FindUserByUsername(username)
	} else {
		err = ErrNotFound
	}
	if errors.Is(err, ErrNotFound) {
		// Fall back to the first active admin.
		var admin User
		dbErr := a.db.Where("role = ? AND disabled = ?", RoleAdmin, false).Order("id asc").First(&admin).Error
		if dbErr != nil {
			return echo.NewHTTPError(http.StatusNotFound, "no admin user available for dev login")
		}
		user = &admin
	} else if err != nil {
		return err
	}
	if user.Disabled {
		return echo.NewHTTPError(http.StatusForbidden, "dev admin account is disabled")
	}
	if err := a.createSession(c, user); err != nil {
		return err
	}
	a.attachUser(c, user)
	a.logger.Warn().Str("username", user.Username).Msg("dev auto-login session created")
	return c.JSON(http.StatusOK, toUserDTO(user))
}

// rejectWhenOIDCRequired blocks local login endpoints in exclusive mode.
func (a *Auth) rejectWhenOIDCRequired() error {
	settings, err := a.GetSettings()
	if err != nil {
		return err
	}
	if settings.OIDCMode == OIDCModeRequired {
		return echo.NewHTTPError(http.StatusForbidden, "local login is disabled; use the configured OIDC provider")
	}
	return nil
}

// mapServiceError converts service-level errors into HTTP errors.
func mapServiceError(err error) error {
	switch {
	case err == nil:
		return nil
	case IsInputError(err):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrConcurrentUpdate):
		return echo.NewHTTPError(http.StatusConflict, "account was modified concurrently; please retry")
	case errors.Is(err, ErrNotFound):
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	default:
		return err
	}
}
