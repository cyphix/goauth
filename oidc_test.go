package goauth

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupOIDC creates an enabled provider pointing at the mock server and
// switches to the given mode. Returns the provider ID.
func setupOIDC(t *testing.T, env *testEnv, mock *mockOIDCServer, mode OIDCMode, autoProvision bool) uint {
	t.Helper()
	admin := env.adminClient()
	name, issuer, clientID, secret := "MockIdP", mock.issuer(), "test-client", "test-secret"
	var provider oidcProviderAdminDTO
	resp := env.doJSON(admin, http.MethodPost, "/auth/admin/oidc", adminOIDCProviderRequest{
		Name: &name, IssuerURL: &issuer, ClientID: &clientID, ClientSecret: &secret, AutoProvision: &autoProvision,
	}, &provider)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp = env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: mode}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return provider.ID
}

// followOIDCFlow drives a browser client through start -> provider ->
// callback and returns the final (non-redirect) response URL path+query.
func followOIDCFlow(t *testing.T, env *testEnv, client *http.Client, providerID uint) *http.Response {
	t.Helper()
	resp, err := client.Get(env.url("/auth/oidc/" + uintToString(providerID) + "/start"))
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

func uintToString(v uint) string {
	return strconv.FormatUint(uint64(v), 10)
}

func TestOIDCLoginAutoProvision(t *testing.T) {
	env := newTestEnv(t, nil)
	mock := newMockOIDCServer(t)
	providerID := setupOIDC(t, env, mock, OIDCModeOptional, true)

	client := env.client()
	resp := followOIDCFlow(t, env, client, providerID)
	// The http.Client follows every redirect: app start -> mock authorize ->
	// app callback -> SPA "/" (404 in tests since no SPA is mounted, but the
	// final URL tells us where we landed).
	assert.Equal(t, "/", resp.Request.URL.Path)
	assert.Empty(t, resp.Request.URL.Query().Get("error"))

	// The session is now authenticated as the auto-provisioned user.
	var me UserDTO
	r := env.doJSON(client, http.MethodGet, "/auth/me", nil, &me)
	require.Equal(t, http.StatusOK, r.StatusCode)
	assert.Equal(t, "mockuser", me.Username)
	assert.Equal(t, RoleUser, me.Role)
	assert.False(t, me.HasPassword)
	assert.True(t, me.OIDCLinked)

	resp = env.doJSON(client, http.MethodPost, "/auth/password", changePasswordRequest{NewPassword: "first-password-1"}, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp = env.doJSON(env.client(), http.MethodPost, "/auth/login",
		loginRequest{Username: "mockuser", Password: "first-password-1"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Second login with the same sub reuses the account (no duplicate).
	client2 := env.client()
	followOIDCFlow(t, env, client2, providerID)
	var me2 UserDTO
	env.doJSON(client2, http.MethodGet, "/auth/me", nil, &me2)
	assert.Equal(t, me.ID, me2.ID)

	// A different sub with a colliding preferred_username gets a suffix.
	mock.Sub = "mock-sub-2"
	client3 := env.client()
	followOIDCFlow(t, env, client3, providerID)
	var me3 UserDTO
	env.doJSON(client3, http.MethodGet, "/auth/me", nil, &me3)
	assert.Equal(t, "mockuser-2", me3.Username)
}

func TestOIDCLoginWithoutAutoProvision(t *testing.T) {
	env := newTestEnv(t, nil)
	mock := newMockOIDCServer(t)
	providerID := setupOIDC(t, env, mock, OIDCModeOptional, false)

	// Unknown subject is rejected and lands on /login?error=not_provisioned.
	client := env.client()
	resp := followOIDCFlow(t, env, client, providerID)
	assert.Equal(t, "/login", resp.Request.URL.Path)
	assert.Equal(t, "not_provisioned", resp.Request.URL.Query().Get("error"))
	r := env.doJSON(client, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, r.StatusCode)

	// Pre-linked users may log in.
	sub := mock.Sub
	user, err := env.auth.CreateUser("linked", "", "", RoleUser)
	require.NoError(t, err)
	require.NoError(t, env.auth.DB().Model(user).Updates(map[string]any{"oidc_provider_id": providerID, "oidc_sub": sub}).Error)

	client2 := env.client()
	resp = followOIDCFlow(t, env, client2, providerID)
	assert.Equal(t, "/", resp.Request.URL.Path)
	var me UserDTO
	env.doJSON(client2, http.MethodGet, "/auth/me", nil, &me)
	assert.Equal(t, "linked", me.Username)
}

func TestOIDCRequiredModeStillAllowsOIDC(t *testing.T) {
	env := newTestEnv(t, nil)
	mock := newMockOIDCServer(t)
	providerID := setupOIDC(t, env, mock, OIDCModeRequired, true)

	// Local login is blocked...
	resp := env.doJSON(env.client(), http.MethodPost, "/auth/login", loginRequest{Username: "admin", Password: "admin-password-1"}, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// ...but the OIDC flow works.
	client := env.client()
	final := followOIDCFlow(t, env, client, providerID)
	assert.Equal(t, "/", final.Request.URL.Path)
	r := env.doJSON(client, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusOK, r.StatusCode)
}

func TestOIDCStartDisabledMode(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.client()
	resp, err := client.Get(env.url("/auth/oidc/1/start"))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestOIDCCallbackStateMismatch(t *testing.T) {
	env := newTestEnv(t, nil)
	mock := newMockOIDCServer(t)
	providerID := setupOIDC(t, env, mock, OIDCModeOptional, true)

	// Start the flow but tamper with the state on the callback.
	client := env.client()
	// Don't follow redirects for this one.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(env.url("/auth/oidc/" + uintToString(providerID) + "/start"))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	resp, err = client.Get(env.url("/auth/oidc/callback?code=fake&state=tampered"))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "error=state_mismatch")
}

func TestOIDCRuntimeReconfiguration(t *testing.T) {
	// Admin edits (e.g. wrong issuer fixed) must apply without restart.
	env := newTestEnv(t, nil)
	mock := newMockOIDCServer(t)
	admin := env.adminClient()

	name, badIssuer, clientID, secret := "MockIdP", "http://127.0.0.1:1/nowhere", "test-client", "test-secret"
	var provider oidcProviderAdminDTO
	resp := env.doJSON(admin, http.MethodPost, "/auth/admin/oidc", adminOIDCProviderRequest{
		Name: &name, IssuerURL: &badIssuer, ClientID: &clientID, ClientSecret: &secret,
	}, &provider)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp = env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: OIDCModeOptional}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Discovery fails -> redirected to login with provider_unavailable.
	client := env.client()
	final := followOIDCFlow(t, env, client, provider.ID)
	assert.Equal(t, "provider_unavailable", final.Request.URL.Query().Get("error"))

	// Fix the issuer through the admin API; next login succeeds immediately.
	goodIssuer := mock.issuer()
	resp = env.doJSON(admin, http.MethodPatch, "/auth/admin/oidc/"+uintToString(provider.ID), adminOIDCProviderRequest{IssuerURL: &goodIssuer}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	client2 := env.client()
	final = followOIDCFlow(t, env, client2, provider.ID)
	assert.Equal(t, "/", final.Request.URL.Path)
	r := env.doJSON(client2, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusOK, r.StatusCode)
}
