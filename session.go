package goauth

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
)

const (
	sessionKeyUserID = "goauth_user_id"

	echoCtxUserKey = "goauth_user"
)

type contextKey string

const userContextKey contextKey = "goauth_user"

func sameSiteLax() http.SameSite { return http.SameSiteLaxMode }

// SessionMiddleware loads/saves the SCS session for every request and
// enforces an Origin-header CSRF check on unsafe methods. Apply it once,
// globally, before any goauth routes or guarded routes.
func (a *Auth) SessionMiddleware() echo.MiddlewareFunc {
	loadAndSave := echo.WrapMiddleware(a.sessions.LoadAndSave)
	originCheck := a.originCheckMiddleware()
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return originCheck(loadAndSave(next))
	}
}

// originCheckMiddleware rejects unsafe cross-origin browser requests. Non
// browser clients without an Origin header pass through (cookies cannot be
// forged without a browser).
func (a *Auth) originCheckMiddleware() echo.MiddlewareFunc {
	allowed := map[string]struct{}{}
	for _, o := range a.cfg.Origins {
		allowed[o] = struct{}{}
	}
	if a.cfg.PublicBaseURL != "" {
		allowed[a.cfg.PublicBaseURL] = struct{}{}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			switch c.Request().Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				return next(c)
			}
			origin := c.Request().Header.Get("Origin")
			if origin == "" || origin == "null" {
				return next(c)
			}
			if _, ok := allowed[origin]; !ok {
				return echo.NewHTTPError(http.StatusForbidden, "origin not allowed")
			}
			return next(c)
		}
	}
}

// createSession renews the session token (fixation protection) and binds it
// to the user.
func (a *Auth) createSession(c echo.Context, user *User) error {
	ctx := c.Request().Context()
	if err := a.sessions.RenewToken(ctx); err != nil {
		return err
	}
	a.sessions.Put(ctx, sessionKeyUserID, int(user.ID))
	return nil
}

// destroySession removes the current session entirely.
func (a *Auth) destroySession(c echo.Context) error {
	return a.sessions.Destroy(c.Request().Context())
}

// sessionUserID returns the logged-in user ID recorded in the session.
func (a *Auth) sessionUserID(c echo.Context) (uint, bool) {
	id := a.sessions.GetInt(c.Request().Context(), sessionKeyUserID)
	if id <= 0 {
		return 0, false
	}
	return uint(id), true
}

// loadSessionUser resolves the session to an active user, or nil when the
// request is unauthenticated. The user is cached on the Echo context.
func (a *Auth) loadSessionUser(c echo.Context) (*User, error) {
	if u, ok := c.Get(echoCtxUserKey).(*User); ok {
		return u, nil
	}
	id, ok := a.sessionUserID(c)
	if !ok {
		return nil, nil
	}
	user, err := a.FindUserByID(id)
	if err != nil {
		if err == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	if user.Disabled {
		return nil, nil
	}
	a.attachUser(c, user)
	return user, nil
}

// attachUser caches the user on the Echo context and the request context (so
// GraphQL resolvers and other context consumers can reach it).
func (a *Auth) attachUser(c echo.Context, user *User) {
	c.Set(echoCtxUserKey, user)
	req := c.Request()
	c.SetRequest(req.WithContext(context.WithValue(req.Context(), userContextKey, user)))
}

// RequireAuthenticated rejects requests without a valid session (401) and
// attaches the user to the request contexts.
func (a *Auth) RequireAuthenticated() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, err := a.loadSessionUser(c)
			if err != nil {
				return err
			}
			if user == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
			}
			return next(c)
		}
	}
}

// RequireRole rejects requests whose session user does not hold the role
// (403), or is unauthenticated (401). Admins pass every role check.
func (a *Auth) RequireRole(role Role) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, err := a.loadSessionUser(c)
			if err != nil {
				return err
			}
			if user == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
			}
			if user.Role != role && user.Role != RoleAdmin {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient role")
			}
			return next(c)
		}
	}
}

// CurrentUser returns the authenticated user attached by RequireAuthenticated
// (or RequireRole), or nil.
func CurrentUser(c echo.Context) *User {
	if u, ok := c.Get(echoCtxUserKey).(*User); ok {
		return u
	}
	return nil
}

// UserFromContext returns the authenticated user from a request context (for
// GraphQL resolvers and services), or nil.
func UserFromContext(ctx context.Context) *User {
	if u, ok := ctx.Value(userContextKey).(*User); ok {
		return u
	}
	return nil
}
