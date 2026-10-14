package goauth

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminUserCRUD(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := env.adminClient()

	// Create.
	var created UserDTO
	resp := env.doJSON(admin, http.MethodPost, "/auth/admin/users", adminCreateUserRequest{Username: "Dave", Password: "dave-password-1", Role: RoleUser}, &created)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "dave", created.Username)
	assert.Equal(t, RoleUser, created.Role)
	assert.True(t, created.HasPassword)

	// Duplicate username rejected.
	resp = env.doJSON(admin, http.MethodPost, "/auth/admin/users", adminCreateUserRequest{Username: "dave", Password: "dave-password-1"}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// List includes both users.
	var users []UserDTO
	resp = env.doJSON(admin, http.MethodGet, "/auth/admin/users", nil, &users)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, users, 2)

	// Promote + password reset.
	role := RoleAdmin
	newPass := "dave-password-2"
	var updated UserDTO
	resp = env.doJSON(admin, http.MethodPatch, fmt.Sprintf("/auth/admin/users/%d", created.ID), adminUpdateUserRequest{Role: &role, Password: &newPass}, &updated)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, RoleAdmin, updated.Role)
	env.login(env.client(), "dave", "dave-password-2")

	// Delete.
	resp = env.doJSON(admin, http.MethodDelete, fmt.Sprintf("/auth/admin/users/%d", created.ID), nil, nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp = env.doJSON(env.client(), http.MethodPost, "/auth/login", loginRequest{Username: "dave", Password: "dave-password-2"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLastAdminProtections(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := env.adminClient()

	adminUser, err := env.auth.FindUserByUsername("admin")
	require.NoError(t, err)

	// Cannot demote, disable or delete the last admin.
	role := RoleUser
	resp := env.doJSON(admin, http.MethodPatch, fmt.Sprintf("/auth/admin/users/%d", adminUser.ID), adminUpdateUserRequest{Role: &role}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	disabled := true
	resp = env.doJSON(admin, http.MethodPatch, fmt.Sprintf("/auth/admin/users/%d", adminUser.ID), adminUpdateUserRequest{Disabled: &disabled}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Deleting self is blocked outright.
	resp = env.doJSON(admin, http.MethodDelete, fmt.Sprintf("/auth/admin/users/%d", adminUser.ID), nil, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// With a second admin, demotion works.
	_, err = env.auth.CreateUser("admin2", "admin2-password-1", "", RoleAdmin)
	require.NoError(t, err)
	resp = env.doJSON(admin, http.MethodPatch, fmt.Sprintf("/auth/admin/users/%d", adminUser.ID), adminUpdateUserRequest{Role: &role}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestOIDCProviderCRUDAndSettings(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := env.adminClient()

	// Mode cannot leave disabled without an enabled provider.
	resp := env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: OIDCModeOptional}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Create a provider.
	name, issuer, clientID, secret := "Authentik", "https://auth.example.com/application/o/app/", "client-id", "client-secret"
	var provider oidcProviderAdminDTO
	resp = env.doJSON(admin, http.MethodPost, "/auth/admin/oidc", adminOIDCProviderRequest{
		Name: &name, IssuerURL: &issuer, ClientID: &clientID, ClientSecret: &secret,
	}, &provider)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, provider.HasClientSecret)
	assert.True(t, provider.Enabled)
	assert.True(t, provider.AutoProvision)

	// Now optional mode works, and /auth/config lists the provider.
	resp = env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: OIDCModeOptional}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var cfg authConfigDTO
	env.doJSON(env.client(), http.MethodGet, "/auth/config", nil, &cfg)
	assert.Equal(t, OIDCModeOptional, cfg.OIDCMode)
	assert.True(t, cfg.PasswordLogin)
	require.Len(t, cfg.OIDCProviders, 1)
	assert.Equal(t, "Authentik", cfg.OIDCProviders[0].Name)

	// Cannot disable or delete the last enabled provider while mode active.
	enabled := false
	resp = env.doJSON(admin, http.MethodPatch, fmt.Sprintf("/auth/admin/oidc/%d", provider.ID), adminOIDCProviderRequest{Enabled: &enabled}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp = env.doJSON(admin, http.MethodDelete, fmt.Sprintf("/auth/admin/oidc/%d", provider.ID), nil, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Required mode hides local login from /auth/config and blocks POST /auth/login.
	resp = env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: OIDCModeRequired}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	env.doJSON(env.client(), http.MethodGet, "/auth/config", nil, &cfg)
	assert.False(t, cfg.PasswordLogin)
	assert.False(t, cfg.Passkeys)
	resp = env.doJSON(env.client(), http.MethodPost, "/auth/login", loginRequest{Username: "admin", Password: "admin-password-1"}, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp = env.doJSON(env.client(), http.MethodPost, "/auth/passkey/login/begin", nil, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Back to disabled: provider hidden from /auth/config, local login restored.
	resp = env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: OIDCModeDisabled}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	env.doJSON(env.client(), http.MethodGet, "/auth/config", nil, &cfg)
	assert.True(t, cfg.PasswordLogin)
	assert.Empty(t, cfg.OIDCProviders)

	// Deleting the provider is allowed now.
	resp = env.doJSON(admin, http.MethodDelete, fmt.Sprintf("/auth/admin/oidc/%d", provider.ID), nil, nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestSecretNeverEchoed(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := env.adminClient()

	name, issuer, clientID, secret := "P", "https://issuer.example", "cid", "super-secret"
	var provider oidcProviderAdminDTO
	env.doJSON(admin, http.MethodPost, "/auth/admin/oidc", adminOIDCProviderRequest{
		Name: &name, IssuerURL: &issuer, ClientID: &clientID, ClientSecret: &secret,
	}, &provider)

	var listed []map[string]any
	env.doJSON(admin, http.MethodGet, "/auth/admin/oidc", nil, &listed)
	require.Len(t, listed, 1)
	_, hasSecretField := listed[0]["clientSecret"]
	assert.False(t, hasSecretField)
	assert.Equal(t, true, listed[0]["hasClientSecret"])

	// Patching without a secret keeps the old one.
	newName := "P2"
	var updated oidcProviderAdminDTO
	env.doJSON(admin, http.MethodPatch, fmt.Sprintf("/auth/admin/oidc/%d", provider.ID), adminOIDCProviderRequest{Name: &newName}, &updated)
	assert.True(t, updated.HasClientSecret)

	row, err := env.auth.findOIDCProvider(provider.ID)
	require.NoError(t, err)
	assert.Equal(t, "super-secret", row.ClientSecret)
}
