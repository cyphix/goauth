package goauth

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func avatarEnv(t *testing.T, mutate func(*Config)) *testEnv {
	t.Helper()
	env := newTestEnv(t, mutate)
	env.auth.RegisterAvatarRoutes(
		env.echo.Group("/api/me/avatar", env.auth.RequireAuthenticated()),
		env.echo.Group("/admin", env.auth.RequireRole(RoleAdmin)),
	)
	// Exercise the exported self handlers without caller authentication too.
	env.echo.PUT("/direct", env.auth.UploadAvatar)
	env.echo.GET("/direct", env.auth.Avatar)
	env.echo.DELETE("/direct", env.auth.DeleteAvatar)
	return env
}

func avatarRequest(t *testing.T, env *testEnv, client *http.Client, method, path string, data []byte) (*http.Response, []byte) {
	t.Helper()
	var body bytes.Buffer
	contentType := ""
	if data != nil {
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormFile("file", "avatar.png")
		require.NoError(t, err)
		_, err = part.Write(data)
		require.NoError(t, err)
		require.NoError(t, writer.Close())
		contentType = writer.FormDataContentType()
	}
	req, err := http.NewRequest(method, env.server.URL+path, &body)
	require.NoError(t, err)
	req.Header.Set("Origin", env.server.URL)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	result, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, result
}

func TestAvatarLifecycle(t *testing.T) {
	env := avatarEnv(t, nil)
	client := env.adminClient()
	var user User
	require.NoError(t, env.auth.db.First(&user, "username = ?", "admin").Error)
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, env.auth.db.Model(&user).Update("updated_at", old).Error)

	resp, _ := avatarRequest(t, env, client, http.MethodGet, "/api/me/avatar", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	image := []byte("\x89PNG\r\n\x1a\nimage bytes")
	resp, _ = avatarRequest(t, env, client, http.MethodPut, "/api/me/avatar", image)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NoError(t, env.auth.db.First(&user, user.ID).Error)
	assert.True(t, user.UpdatedAt.After(old))
	var stored UserAvatar
	require.NoError(t, env.auth.db.First(&stored, "user_id = ?", user.ID).Error)
	assert.Equal(t, "image/png", stored.ContentType)
	assert.False(t, stored.UpdatedAt.IsZero())

	resp, body := avatarRequest(t, env, client, http.MethodGet, "/api/me/avatar", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, image, body)
	assert.Equal(t, "image/png", resp.Header.Get("Content-Type"))
	assert.Equal(t, "private, max-age=0, must-revalidate", resp.Header.Get("Cache-Control"))

	replacement := []byte("GIF89areplacement bytes")
	resp, _ = avatarRequest(t, env, client, http.MethodPut, "/api/me/avatar", replacement)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp, body = avatarRequest(t, env, client, http.MethodGet, fmt.Sprintf("/admin/users/%d/avatar", user.ID), nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, replacement, body)
	assert.Equal(t, "image/gif", resp.Header.Get("Content-Type"))
	var count int64
	require.NoError(t, env.auth.db.Model(&UserAvatar{}).Where("user_id = ?", user.ID).Count(&count).Error)
	assert.EqualValues(t, 1, count)

	require.NoError(t, env.auth.db.Model(&user).Update("updated_at", old).Error)
	resp, _ = avatarRequest(t, env, client, http.MethodDelete, "/api/me/avatar", nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.NoError(t, env.auth.db.First(&user, user.ID).Error)
	assert.True(t, user.UpdatedAt.After(old))
	resp, _ = avatarRequest(t, env, client, http.MethodGet, "/api/me/avatar", nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp, _ = avatarRequest(t, env, client, http.MethodDelete, "/api/me/avatar", nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestAvatarUploadValidation(t *testing.T) {
	env := avatarEnv(t, func(cfg *Config) { cfg.MaxAvatarBytes = 1024 })
	client := env.adminClient()
	for _, data := range [][]byte{nil, {}, []byte("not an image")} {
		resp, _ := avatarRequest(t, env, client, http.MethodPut, "/api/me/avatar", data)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
	resp, _ := avatarRequest(t, env, client, http.MethodPut, "/api/me/avatar", bytes.Repeat([]byte("x"), 1025))
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	resp, _ = avatarRequest(t, env, client, http.MethodGet, "/api/me/avatar", nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestAvatarDefaultUploadLimit(t *testing.T) {
	env := avatarEnv(t, nil)
	assert.Equal(t, DefaultMaxAvatarBytes, env.auth.cfg.MaxAvatarBytes)
	resp, _ := avatarRequest(t, env, env.adminClient(), http.MethodPut, "/api/me/avatar", bytes.Repeat([]byte("x"), int(DefaultMaxAvatarBytes)+1))
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestAvatarAuthorization(t *testing.T) {
	env := avatarEnv(t, nil)
	for _, path := range []string{"/direct", "/api/me/avatar"} {
		for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodDelete} {
			resp, _ := avatarRequest(t, env, env.client(), method, path, nil)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		}
	}
	resp, _ := avatarRequest(t, env, env.client(), http.MethodGet, "/admin/users/1/avatar", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_, err := env.auth.CreateUser("regular", "regular-password", "", RoleUser)
	require.NoError(t, err)
	client := env.client()
	env.login(client, "regular", "regular-password")
	resp, _ = avatarRequest(t, env, client, http.MethodGet, "/admin/users/1/avatar", nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	client = env.adminClient()
	for _, id := range []string{"0", "nope", "-1", "4294967296"} {
		resp, _ = avatarRequest(t, env, client, http.MethodGet, "/admin/users/"+id+"/avatar", nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
	resp, _ = avatarRequest(t, env, client, http.MethodGet, "/admin/users/999999/avatar", nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestAvatarForeignKeyCascade(t *testing.T) {
	env := avatarEnv(t, nil)
	user, err := env.auth.CreateUser("avatar-owner", "", "", RoleUser)
	require.NoError(t, err)
	require.NoError(t, env.auth.db.Create(&UserAvatar{UserID: user.ID, ContentType: "image/png", Data: []byte("image")}).Error)
	require.NoError(t, env.auth.db.Unscoped().Delete(user).Error)
	var count int64
	require.NoError(t, env.auth.db.Model(&UserAvatar{}).Where("user_id = ?", user.ID).Count(&count).Error)
	assert.Zero(t, count)
	assert.Error(t, env.auth.db.Create(&UserAvatar{UserID: user.ID, ContentType: "image/png", Data: []byte("image")}).Error)
}

func TestAvatarDatabaseErrors(t *testing.T) {
	env := avatarEnv(t, nil)
	client := env.adminClient()
	require.NoError(t, env.auth.db.Migrator().DropTable(&UserAvatar{}))
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		resp, _ := avatarRequest(t, env, client, method, "/api/me/avatar", []byte("GIF89aimage"))
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	}
	resp, _ := avatarRequest(t, env, client, http.MethodGet, "/admin/users/1/avatar", nil)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
