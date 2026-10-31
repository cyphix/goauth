package goauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	logg "github.com/cyphix/gologg"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var testDBCounter atomic.Int64

func init() {
	logg.SetSilent(true)
}

// newTestDB returns an isolated database for one test. Default: in-memory
// SQLite. Set TEST_DATABASE_URL to a Postgres DSN to run the whole suite
// against real Postgres (validates jsonb columns and partial indexes on the
// production engine). Tests run serially, so Postgres mode drops the auth
// tables between tests for isolation.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	gormCfg := &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)}

	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		db, err := gorm.Open(postgres.Open(dsn), gormCfg)
		require.NoError(t, err)
		require.NoError(t, db.Migrator().DropTable(
			"auth_webauthn_credentials", "auth_oidc_providers", "auth_settings", "auth_users",
		))
		sqlDB, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { _ = sqlDB.Close() })
		return db
	}

	dsn := fmt.Sprintf("file:goauth_test_%d?mode=memory&cache=shared", testDBCounter.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), gormCfg)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// Keep the shared in-memory database alive for the whole test and
	// serialize access (shared-cache SQLite locks under concurrency).
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// testEnv is a fully wired goauth instance behind an httptest server.
type testEnv struct {
	t      *testing.T
	auth   *Auth
	echo   *echo.Echo
	server *httptest.Server
}

// newTestEnv builds the environment. mutate may adjust the Config before New
// (e.g. enable DevAutoLogin); the server URL fields are filled in afterwards
// via a second pass because PublicBaseURL depends on the listener.
func newTestEnv(t *testing.T, mutate func(*Config)) *testEnv {
	t.Helper()

	db := newTestDB(t)
	rdb := newTestRedis(t)

	e := echo.New()
	defaultErrorHandler := e.HTTPErrorHandler
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if _, ok := err.(*echo.HTTPError); !ok {
			t.Logf("unhandled server error on %s %s: %v", c.Request().Method, c.Request().URL, err)
		}
		defaultErrorHandler(err, c)
	}
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)

	cfg := Config{
		DB:                db,
		Redis:             rdb,
		RPDisplayName:     "goauth test",
		RPID:              "localhost",
		Origins:           []string{server.URL},
		PublicBaseURL:     server.URL,
		InitAdminUsername: "admin",
		InitAdminPassword: "admin-password-1",
	}
	if mutate != nil {
		mutate(&cfg)
	}

	a, err := New(cfg)
	require.NoError(t, err)

	e.Use(a.SessionMiddleware())
	a.RegisterRoutes(e.Group("/auth"))
	e.GET("/protected", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello "+CurrentUser(c).Username)
	}, a.RequireAuthenticated())
	e.GET("/admin-only", func(c echo.Context) error {
		return c.String(http.StatusOK, "admin "+CurrentUser(c).Username)
	}, a.RequireRole(RoleAdmin))

	return &testEnv{t: t, auth: a, echo: e, server: server}
}

// client returns an HTTP client with its own cookie jar (one browser).
func (env *testEnv) client() *http.Client {
	jar, err := cookiejar.New(nil)
	require.NoError(env.t, err)
	return &http.Client{Jar: jar}
}

func (env *testEnv) url(path string) string { return env.server.URL + path }

// doJSON issues a JSON request and decodes the response body into out (when
// non-nil). It returns the raw response for status assertions.
func (env *testEnv) doJSON(client *http.Client, method, path string, body any, out any) *http.Response {
	return env.doJSONWithHeaders(client, method, path, body, out, nil)
}

func (env *testEnv) doJSONWithHeaders(client *http.Client, method, path string, body any, out any, headers map[string]string) *http.Response {
	env.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(env.t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, env.url(path), reader)
	require.NoError(env.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	require.NoError(env.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(env.t, err)
	if out != nil && len(raw) > 0 {
		require.NoError(env.t, json.Unmarshal(raw, out), "body: %s", raw)
	}
	return resp
}

// login authenticates the client with username/password and asserts success.
func (env *testEnv) login(client *http.Client, username, password string) UserDTO {
	env.t.Helper()
	var user UserDTO
	resp := env.doJSON(client, http.MethodPost, "/auth/login", loginRequest{Username: username, Password: password}, &user)
	require.Equal(env.t, http.StatusOK, resp.StatusCode)
	return user
}

// adminClient returns a client logged in as the init admin.
func (env *testEnv) adminClient() *http.Client {
	client := env.client()
	env.login(client, "admin", "admin-password-1")
	return client
}
