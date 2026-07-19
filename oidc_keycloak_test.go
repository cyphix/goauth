package goauth

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	keycloakImage        = "quay.io/keycloak/keycloak:26.0"
	keycloakRealm        = "goauth-test"
	keycloakClientID     = "goauth-test"
	keycloakClientSecret = "goauth-test-secret"
	keycloakUsername     = "kcuser"
	keycloakPassword     = "KcUser123!"
)

// startKeycloak boots a disposable Keycloak in start-dev mode with the test
// realm imported, and returns the issuer URL. Skips when Docker is not
// available.
func startKeycloak(t *testing.T) string {
	t.Helper()

	realmPath, err := filepath.Abs("testdata/keycloak-realm.json")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        keycloakImage,
			ExposedPorts: []string{"8080/tcp"},
			Cmd:          []string{"start-dev", "--import-realm"},
			Env: map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
				"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
			},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      realmPath,
					ContainerFilePath: "/opt/keycloak/data/import/keycloak-realm.json",
					FileMode:          0o644,
				},
			},
			WaitingFor: wait.ForHTTP("/realms/" + keycloakRealm + "/.well-known/openid-configuration").
				WithPort("8080/tcp").
				WithStartupTimeout(4 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("keycloak container unavailable (start Docker to run this test): %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "8080/tcp")
	require.NoError(t, err)
	return fmt.Sprintf("http://%s:%s/realms/%s", host, port.Port(), keycloakRealm)
}

var keycloakFormActionPattern = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)

// submitKeycloakLogin parses Keycloak's server-rendered login page and posts
// the credentials, returning the final response after all redirects (the
// http.Client carries both app and Keycloak cookies in its jar).
func submitKeycloakLogin(t *testing.T, client *http.Client, loginPage *http.Response, username, password string) *http.Response {
	t.Helper()

	body, err := io.ReadAll(loginPage.Body)
	require.NoError(t, err)
	loginPage.Body.Close()

	match := keycloakFormActionPattern.FindSubmatch(body)
	require.NotNil(t, match, "no login form found in Keycloak response: %.512s", body)
	actionURL := html.UnescapeString(string(match[1]))

	form := url.Values{
		"username":     {username},
		"password":     {password},
		"credentialId": {""},
	}
	resp, err := client.PostForm(actionURL, form)
	require.NoError(t, err)
	return resp
}

// TestOIDCKeycloakFullFlow drives the complete authorization-code flow (PKCE,
// state, nonce) against a real Keycloak instance in Docker: admin configures
// the provider at runtime, an unknown Keycloak user logs in and gets
// auto-provisioned, and the second login reuses the same account.
func TestOIDCKeycloakFullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Keycloak integration test in -short mode")
	}
	issuer := startKeycloak(t)
	env := newTestEnv(t, nil)

	// Configure the provider through the admin API, exactly as an admin
	// would from the UI.
	admin := env.adminClient()
	name, clientID, secret := "Keycloak", keycloakClientID, keycloakClientSecret
	issuerURL := issuer
	var provider oidcProviderAdminDTO
	resp := env.doJSON(admin, http.MethodPost, "/auth/admin/oidc", adminOIDCProviderRequest{
		Name: &name, IssuerURL: &issuerURL, ClientID: &clientID, ClientSecret: &secret,
	}, &provider)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp = env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: OIDCModeOptional}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Fresh browser: start the flow, land on Keycloak's login form.
	browser := env.client()
	loginPage, err := browser.Get(env.url("/auth/oidc/" + uintToString(provider.ID) + "/start"))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, loginPage.StatusCode)
	require.Contains(t, loginPage.Request.URL.String(), issuer, "should have been redirected to Keycloak")

	// Submit credentials; Keycloak redirects back to /auth/oidc/callback,
	// which finishes the login and redirects to the SPA root.
	final := submitKeycloakLogin(t, browser, loginPage, keycloakUsername, keycloakPassword)
	defer final.Body.Close()
	require.Equal(t, "/", final.Request.URL.Path, "expected to land on the app root, got %s", final.Request.URL)
	require.Empty(t, final.Request.URL.Query().Get("error"))

	// Session is live; user was auto-provisioned from preferred_username.
	var me UserDTO
	r := env.doJSON(browser, http.MethodGet, "/auth/me", nil, &me)
	require.Equal(t, http.StatusOK, r.StatusCode)
	assert.Equal(t, keycloakUsername, me.Username)
	assert.Equal(t, RoleUser, me.Role)
	assert.True(t, me.OIDCLinked)
	assert.False(t, me.HasPassword)

	// Second login from another browser reuses the same account (Keycloak
	// SSO may skip the form; handle both cases).
	browser2 := env.client()
	page2, err := browser2.Get(env.url("/auth/oidc/" + uintToString(provider.ID) + "/start"))
	require.NoError(t, err)
	var final2 *http.Response
	if strings.Contains(page2.Request.URL.String(), issuer) {
		final2 = submitKeycloakLogin(t, browser2, page2, keycloakUsername, keycloakPassword)
	} else {
		final2 = page2
	}
	defer final2.Body.Close()
	require.Equal(t, "/", final2.Request.URL.Path)

	var me2 UserDTO
	r = env.doJSON(browser2, http.MethodGet, "/auth/me", nil, &me2)
	require.Equal(t, http.StatusOK, r.StatusCode)
	assert.Equal(t, me.ID, me2.ID, "second Keycloak login must reuse the provisioned account")

	// Exclusive mode: local login rejected, Keycloak login still works.
	resp = env.doJSON(admin, http.MethodPut, "/auth/admin/settings", settingsDTO{OIDCMode: OIDCModeRequired}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp = env.doJSON(env.client(), http.MethodPost, "/auth/login", loginRequest{Username: "admin", Password: "admin-password-1"}, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	browser3 := env.client()
	page3, err := browser3.Get(env.url("/auth/oidc/" + uintToString(provider.ID) + "/start"))
	require.NoError(t, err)
	var final3 *http.Response
	if strings.Contains(page3.Request.URL.String(), issuer) {
		final3 = submitKeycloakLogin(t, browser3, page3, keycloakUsername, keycloakPassword)
	} else {
		final3 = page3
	}
	defer final3.Body.Close()
	r = env.doJSON(browser3, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusOK, r.StatusCode)
}
