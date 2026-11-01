package goauth

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateProfileUsernameAndEmail(t *testing.T) {
	env := newTestEnv(t, nil)
	client := env.adminClient()

	username := "admin-renamed"
	email := "Admin@Example.COM"
	var updated UserDTO
	resp := env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{Username: &username, Email: &email}, &updated)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "admin-renamed", updated.Username)
	require.NotNil(t, updated.Email)
	assert.Equal(t, "admin@example.com", *updated.Email)

	// Empty patch is rejected.
	resp = env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Invalid username and email rejected.
	bad := "!!bad!!"
	resp = env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{Username: &bad}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	badEmail := "not-an-email"
	resp = env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{Email: &badEmail}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Clearing email stores NULL.
	empty := ""
	resp = env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{Email: &empty}, &updated)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Nil(t, updated.Email)
}

func TestUpdateProfileUniqueness(t *testing.T) {
	env := newTestEnv(t, nil)
	_, err := env.auth.CreateUser("taken", "taken-password-1", "taken@example.com", RoleUser)
	require.NoError(t, err)

	client := env.adminClient()
	conflict := "taken"
	resp := env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{Username: &conflict}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	conflictEmail := "taken@example.com"
	resp = env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{Email: &conflictEmail}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Setting the same values is a no-op success.
	same := "admin"
	sameEmail := ""
	resp = env.doJSON(client, http.MethodPatch, "/auth/me", updateProfileRequest{Username: &same, Email: &sameEmail}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestLoginWithEmail(t *testing.T) {
	env := newTestEnv(t, nil)
	_, err := env.auth.CreateUser("erin", "erin-password-1", "Erin@Example.com", RoleUser)
	require.NoError(t, err)

	// Identifier field accepts the email (any case).
	user := env.login(env.client(), "erin@example.com", "erin-password-1")
	assert.Equal(t, "erin", user.Username)

	resp := env.doJSON(env.client(), http.MethodPost, "/auth/login",
		loginRequest{Identifier: "ERIN@EXAMPLE.COM", Password: "erin-password-1"}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Username login still works, wrong password still rejected.
	user = env.login(env.client(), "erin", "erin-password-1")
	assert.Equal(t, "erin", user.Username)
	resp = env.doJSON(env.client(), http.MethodPost, "/auth/login",
		loginRequest{Identifier: "erin@example.com", Password: "wrong"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestPasswordlessAccountSetsPassword(t *testing.T) {
	env := newTestEnv(t, nil)
	user, err := env.auth.CreateUser("nopass", "", "", RoleUser)
	require.NoError(t, err)

	// ChangePassword on a passwordless account sets the initial password
	// without a current password.
	require.NoError(t, env.auth.ChangePassword(user.ID, "", "first-password-1"))
	env.login(env.client(), "nopass", "first-password-1")

	// Once set, the current password is required again.
	err = env.auth.ChangePassword(user.ID, "wrong", "second-password-1")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	require.NoError(t, env.auth.ChangePassword(user.ID, "first-password-1", "second-password-1"))
	env.login(env.client(), "nopass", "second-password-1")
}

func TestOIDCLinkedAccountCannotSetInitialPassword(t *testing.T) {
	env := newTestEnv(t, nil)
	user, err := env.auth.CreateUser("oidc-nopass", "", "", RoleUser)
	require.NoError(t, err)
	require.NoError(t, env.auth.DB().Model(user).Update("oidc_sub", "oidc-nopass-sub").Error)

	err = env.auth.ChangePassword(user.ID, "", "first-password-1")
	assert.ErrorIs(t, err, ErrPasswordManagedByIdP)

	user, err = env.auth.FindUserByID(user.ID)
	require.NoError(t, err)
	assert.False(t, user.HasPassword())

	require.NoError(t, env.auth.SetPassword(user.ID, "admin-set-pass-1"))
	require.NoError(t, env.auth.ChangePassword(user.ID, "admin-set-pass-1", "updated-password-1"))
}

func TestAdminCreateAndPatchEmail(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := env.adminClient()

	var created UserDTO
	resp := env.doJSON(admin, http.MethodPost, "/auth/admin/users",
		adminCreateUserRequest{Username: "frank", Password: "frank-password-1", Email: "frank@example.com"}, &created)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	require.NotNil(t, created.Email)
	assert.Equal(t, "frank@example.com", *created.Email)

	// Admin can rename + change email.
	newName := "frank-renamed"
	newEmail := "frank2@example.com"
	var patched UserDTO
	resp = env.doJSON(admin, http.MethodPatch, fmt.Sprintf("/auth/admin/users/%d", created.ID),
		adminUpdateUserRequest{Username: &newName, Email: &newEmail}, &patched)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "frank-renamed", patched.Username)
	require.NotNil(t, patched.Email)
	assert.Equal(t, "frank2@example.com", *patched.Email)

	// Renamed user logs in with the new name and the email.
	env.login(env.client(), "frank-renamed", "frank-password-1")
	env.login(env.client(), "frank2@example.com", "frank-password-1")
}
