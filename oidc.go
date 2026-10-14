package goauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

const sessionKeyOIDCFlow = "goauth_oidc_flow"

// oidcRuntime caches OIDC discovery documents per provider row so that
// admin-driven configuration changes apply at runtime without restarts.
type oidcRuntime struct {
	auth  *Auth
	mu    sync.Mutex
	cache map[uint]*oidcClient
}

type oidcClient struct {
	row      OIDCProvider
	provider *oidc.Provider
}

func newOIDCRuntime(a *Auth) *oidcRuntime {
	return &oidcRuntime{auth: a, cache: map[uint]*oidcClient{}}
}

// invalidate drops the cached discovery for a provider (call after admin
// updates or deletes).
func (r *oidcRuntime) invalidate(providerID uint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, providerID)
}

// client returns a ready OIDC client for an enabled provider, running
// discovery when the cache is cold or the row changed.
func (r *oidcRuntime) client(ctx context.Context, providerID uint) (*oidcClient, error) {
	var row OIDCProvider
	if err := r.auth.db.First(&row, providerID).Error; err != nil {
		return nil, ErrNotFound
	}
	if !row.Enabled {
		return nil, ErrInvalidInput("provider is disabled")
	}

	r.mu.Lock()
	cached, ok := r.cache[providerID]
	r.mu.Unlock()
	if ok && cached.row.UpdatedAt.Equal(row.UpdatedAt) {
		return cached, nil
	}

	discoverCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discoverCtx, strings.TrimRight(row.IssuerURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", row.IssuerURL, err)
	}

	client := &oidcClient{row: row, provider: provider}
	r.mu.Lock()
	r.cache[providerID] = client
	r.mu.Unlock()
	return client, nil
}

func (a *Auth) oidcRedirectURL() string {
	return a.cfg.PublicBaseURL + a.cfg.MountPath + "/oidc/callback"
}

func (c *oidcClient) oauth2Config(a *Auth) oauth2.Config {
	scopes := []string{oidc.ScopeOpenID, "profile"}
	for _, s := range strings.Fields(c.row.Scopes) {
		if s != oidc.ScopeOpenID && s != "profile" {
			scopes = append(scopes, s)
		}
	}
	return oauth2.Config{
		ClientID:     c.row.ClientID,
		ClientSecret: c.row.ClientSecret,
		Endpoint:     c.provider.Endpoint(),
		RedirectURL:  a.oidcRedirectURL(),
		Scopes:       scopes,
	}
}

func (a *Auth) registerOIDCRoutes(g *echo.Group) {
	g.GET("/oidc/:id/start", a.handleOIDCStart)
	g.GET("/oidc/callback", a.handleOIDCCallback)
}

// oidcFlowState is the per-login state stored in the session between the
// start redirect and the provider callback.
type oidcFlowState struct {
	ProviderID uint   `json:"providerId"`
	State      string `json:"state"`
	Nonce      string `json:"nonce"`
	Verifier   string `json:"verifier"`
	Next       string `json:"next"`
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// safeNextPath only allows same-site absolute paths for post-login redirects.
func safeNextPath(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

func (a *Auth) handleOIDCStart(c echo.Context) error {
	settings, err := a.GetSettings()
	if err != nil {
		return err
	}
	if settings.OIDCMode == OIDCModeDisabled {
		return echo.NewHTTPError(http.StatusForbidden, "oidc login is disabled")
	}
	if a.cfg.PublicBaseURL == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "goauth: PublicBaseURL is not configured")
	}
	id, err := paramID(c)
	if err != nil {
		return err
	}
	client, err := a.oidc.client(c.Request().Context(), id)
	if err != nil {
		a.logger.Error().Err(err).Uint("provider", id).Msg("oidc start failed")
		return a.oidcFailureRedirect(c, "provider_unavailable")
	}

	state, err := randomToken()
	if err != nil {
		return err
	}
	nonce, err := randomToken()
	if err != nil {
		return err
	}
	verifier := oauth2.GenerateVerifier()

	flow := oidcFlowState{
		ProviderID: id,
		State:      state,
		Nonce:      nonce,
		Verifier:   verifier,
		Next:       safeNextPath(c.QueryParam("next")),
	}
	raw, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	a.sessions.Put(c.Request().Context(), sessionKeyOIDCFlow, string(raw))

	oauthCfg := client.oauth2Config(a)
	authURL := oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	return c.Redirect(http.StatusFound, authURL)
}

func (a *Auth) handleOIDCCallback(c echo.Context) error {
	ctx := c.Request().Context()

	raw := a.sessions.PopString(ctx, sessionKeyOIDCFlow)
	if raw == "" {
		return a.oidcFailureRedirect(c, "no_pending_login")
	}
	var flow oidcFlowState
	if err := json.Unmarshal([]byte(raw), &flow); err != nil {
		return err
	}

	if errParam := c.QueryParam("error"); errParam != "" {
		a.logger.Warn().Str("error", errParam).Str("description", c.QueryParam("error_description")).Msg("oidc provider returned an error")
		return a.oidcFailureRedirect(c, "provider_error")
	}
	if c.QueryParam("state") == "" || c.QueryParam("state") != flow.State {
		return a.oidcFailureRedirect(c, "state_mismatch")
	}

	client, err := a.oidc.client(ctx, flow.ProviderID)
	if err != nil {
		a.logger.Error().Err(err).Uint("provider", flow.ProviderID).Msg("oidc callback: provider unavailable")
		return a.oidcFailureRedirect(c, "provider_unavailable")
	}
	oauthCfg := client.oauth2Config(a)

	token, err := oauthCfg.Exchange(ctx, c.QueryParam("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		a.logger.Warn().Err(err).Msg("oidc code exchange failed")
		return a.oidcFailureRedirect(c, "exchange_failed")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return a.oidcFailureRedirect(c, "missing_id_token")
	}
	idToken, err := client.provider.Verifier(&oidc.Config{ClientID: client.row.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		a.logger.Warn().Err(err).Msg("oidc id token verification failed")
		return a.oidcFailureRedirect(c, "invalid_id_token")
	}
	if idToken.Nonce != flow.Nonce {
		return a.oidcFailureRedirect(c, "nonce_mismatch")
	}

	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return a.oidcFailureRedirect(c, "invalid_claims")
	}
	if claims.Sub == "" {
		return a.oidcFailureRedirect(c, "missing_subject")
	}

	email := ""
	if claims.EmailVerified {
		email = claims.Email
	}
	user, err := a.resolveOIDCUser(&client.row, claims.Sub, claims.PreferredUsername, claims.Name, email)
	if err != nil {
		a.logger.Warn().Err(err).Str("sub", claims.Sub).Msg("oidc user resolution failed")
		return a.oidcFailureRedirect(c, "not_provisioned")
	}
	if user.Disabled {
		return a.oidcFailureRedirect(c, "account_disabled")
	}

	if err := a.createSession(c, user); err != nil {
		return err
	}
	a.logger.Info().Str("username", user.Username).Uint("provider", client.row.ID).Msg("oidc login")
	return c.Redirect(http.StatusFound, a.cfg.PublicBaseURL+flow.Next)
}

// oidcFailureRedirect sends the browser back to the SPA login page with an
// error code (the login page shows it instead of auto-redirecting, avoiding
// redirect loops in required mode).
func (a *Auth) oidcFailureRedirect(c echo.Context, code string) error {
	target := a.cfg.PublicBaseURL + "/login?" + url.Values{"error": {code}}.Encode()
	return c.Redirect(http.StatusFound, target)
}

// resolveOIDCUser finds the linked account for (provider, sub), provisioning
// one when the provider allows it.
func (a *Auth) resolveOIDCUser(provider *OIDCProvider, sub, preferredUsername, name, email string) (*User, error) {
	var user User
	err := a.db.Where("oidc_provider_id = ? AND oidc_sub = ?", provider.ID, sub).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !provider.AutoProvision {
		return nil, ErrInvalidInput("account is not provisioned for this provider")
	}

	username, err := a.uniqueUsername(firstNonEmpty(preferredUsername, name, "user-"+sub))
	if err != nil {
		return nil, err
	}
	created := &User{
		Username:       username,
		Role:           RoleUser,
		OIDCProviderID: &provider.ID,
		OIDCSub:        &sub,
	}
	// Adopt the verified email claim when it is valid and unused; never
	// fail a login over it.
	if addr := NormalizeEmail(email); addr != "" && validateEmail(addr) == nil {
		var taken int64
		if a.db.Model(&User{}).Where("email = ?", addr).Count(&taken).Error == nil && taken == 0 {
			created.Email = &addr
		}
	}
	if err := a.db.Create(created).Error; err != nil {
		return nil, err
	}
	a.logger.Info().Str("username", username).Uint("provider", provider.ID).Msg("auto-provisioned oidc user")
	return created, nil
}

// uniqueUsername normalizes the candidate and appends a numeric suffix until
// it is free.
func (a *Auth) uniqueUsername(candidate string) (string, error) {
	base := sanitizeUsername(candidate)
	name := base
	for i := 2; ; i++ {
		var count int64
		if err := a.db.Model(&User{}).Where("username = ?", name).Count(&count).Error; err != nil {
			return "", err
		}
		if count == 0 {
			return name, nil
		}
		name = fmt.Sprintf("%s-%d", base, i)
		if i > 500 {
			return "", ErrInvalidInput("could not derive a unique username")
		}
	}
}

// sanitizeUsername coerces arbitrary IdP-provided names into the local
// username charset.
func sanitizeUsername(raw string) string {
	lowered := NormalizeUsername(raw)
	var b strings.Builder
	for _, r := range lowered {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	name := strings.Trim(b.String(), "._-")
	if len(name) < 3 {
		name = "user-" + name
		name = strings.Trim(name, "._-")
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
