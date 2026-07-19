package goauth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitAdminBootstrap(t *testing.T) {
	env := newTestEnv(t, nil)

	admin, err := env.auth.FindUserByUsername("admin")
	require.NoError(t, err)
	assert.Equal(t, RoleAdmin, admin.Role)
	assert.True(t, admin.HasPassword())

	// Re-running New against the same DB must not create a second admin.
	cfg := env.auth.cfg
	cfg.InitAdminUsername = "other-admin"
	cfg.InitAdminPassword = "other-password-1"
	_, err = New(cfg)
	require.NoError(t, err)
	_, err = env.auth.FindUserByUsername("other-admin")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPasswordLoginLogoutMe(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.client()

	// Unauthenticated /me and guarded route.
	resp := env.doJSON(client, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp = env.doJSON(client, http.MethodGet, "/protected", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Wrong password.
	resp = env.doJSON(client, http.MethodPost, "/auth/login", loginRequest{Username: "admin", Password: "wrong-password"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Correct login.
	user := env.login(client, "admin", "admin-password-1")
	assert.Equal(t, "admin", user.Username)
	assert.Equal(t, RoleAdmin, user.Role)

	// Session works for /me and guarded routes.
	var me UserDTO
	resp = env.doJSON(client, http.MethodGet, "/auth/me", nil, &me)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "admin", me.Username)

	req, _ := http.NewRequest(http.MethodGet, env.url("/protected"), nil)
	res, err := client.Do(req)
	require.NoError(t, err)
	body := make([]byte, 64)
	n, _ := res.Body.Read(body)
	res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "hello admin", string(body[:n]))

	// Logout kills the session.
	resp = env.doJSON(client, http.MethodPost, "/auth/logout", nil, nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp = env.doJSON(client, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLoginUsernameCaseInsensitive(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.client()
	user := env.login(client, "ADMIN", "admin-password-1")
	assert.Equal(t, "admin", user.Username)
}

func TestDisabledUserCannotLoginOrKeepSession(t *testing.T) {
	env := newTestEnv(t, nil)
	_, err := env.auth.CreateUser("bob", "bob-password-1", RoleUser)
	require.NoError(t, err)

	client := env.client()
	env.login(client, "bob", "bob-password-1")

	// Disable bob mid-session.
	bob, err := env.auth.FindUserByUsername("bob")
	require.NoError(t, err)
	disabled := true
	_, err = env.auth.UpdateUser(bob.ID, UserPatch{Disabled: &disabled})
	require.NoError(t, err)

	// Existing session no longer resolves.
	resp := env.doJSON(client, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Fresh login rejected.
	resp = env.doJSON(env.client(), http.MethodPost, "/auth/login", loginRequest{Username: "bob", Password: "bob-password-1"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRequireRole(t *testing.T) {
	env := newTestEnv(t, nil)
	_, err := env.auth.CreateUser("carol", "carol-password-1", RoleUser)
	require.NoError(t, err)

	userClient := env.client()
	env.login(userClient, "carol", "carol-password-1")
	resp := env.doJSON(userClient, http.MethodGet, "/admin-only", nil, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp = env.doJSON(userClient, http.MethodGet, "/auth/admin/users", nil, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	adminClient := env.adminClient()
	resp = env.doJSON(adminClient, http.MethodGet, "/admin-only", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestChangePassword(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.adminClient()

	// Wrong current password.
	resp := env.doJSON(client, http.MethodPost, "/auth/password", changePasswordRequest{CurrentPassword: "nope", NewPassword: "new-password-12"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Too-short new password.
	resp = env.doJSON(client, http.MethodPost, "/auth/password", changePasswordRequest{CurrentPassword: "admin-password-1", NewPassword: "short"}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Successful change; old password stops working.
	resp = env.doJSON(client, http.MethodPost, "/auth/password", changePasswordRequest{CurrentPassword: "admin-password-1", NewPassword: "new-password-12"}, nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	fresh := env.client()
	resp = env.doJSON(fresh, http.MethodPost, "/auth/login", loginRequest{Username: "admin", Password: "admin-password-1"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env.login(fresh, "admin", "new-password-12")
}

func TestLoginThrottle(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.client()

	for i := 0; i < throttleMaxAttempts; i++ {
		resp := env.doJSON(client, http.MethodPost, "/auth/login", loginRequest{Username: "admin", Password: "wrong"}, nil)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
	// Attempt N+1 is throttled even with the right password.
	resp := env.doJSON(client, http.MethodPost, "/auth/login", loginRequest{Username: "admin", Password: "admin-password-1"}, nil)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

func TestOriginCheckCSRF(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.client()

	req, err := http.NewRequest(http.MethodPost, env.url("/auth/login"), strings.NewReader(`{"username":"admin","password":"admin-password-1"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Allowed origin passes.
	req, err = http.NewRequest(http.MethodPost, env.url("/auth/login"), strings.NewReader(`{"username":"admin","password":"admin-password-1"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", env.server.URL)
	resp, err = client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDevAutoLogin(t *testing.T) {
	env := newTestEnv(t, func(cfg *Config) { cfg.DevAutoLogin = true })
	client := env.client()

	var cfg authConfigDTO
	resp := env.doJSON(client, http.MethodGet, "/auth/config", nil, &cfg)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, cfg.DevAutoLogin)

	var user UserDTO
	resp = env.doJSON(client, http.MethodPost, "/auth/dev/login", nil, &user)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "admin", user.Username)
	assert.Equal(t, RoleAdmin, user.Role)

	resp = env.doJSON(client, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDevLoginRouteAbsentByDefault(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.client()

	var cfg authConfigDTO
	env.doJSON(client, http.MethodGet, "/auth/config", nil, &cfg)
	assert.False(t, cfg.DevAutoLogin)

	// The route is not registered; Echo answers 404 (or 401 via the group
	// catch-all). Either way no session may be created.
	resp := env.doJSON(client, http.MethodPost, "/auth/dev/login", nil, nil)
	assert.Contains(t, []int{http.StatusNotFound, http.StatusUnauthorized}, resp.StatusCode)
	resp = env.doJSON(client, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
