package goauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockOIDCServer is a minimal OpenID Connect provider for tests: discovery,
// JWKS, authorize (auto-approves) and token endpoints with RS256 id tokens.
type mockOIDCServer struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	mu    sync.Mutex
	codes map[string]mockAuthCode
	// Subject and claims the next logins authenticate as.
	Sub               string
	PreferredUsername string
}

type mockAuthCode struct {
	nonce       string
	redirectURI string
}

func newMockOIDCServer(t *testing.T) *mockOIDCServer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	m := &mockOIDCServer{
		t:                 t,
		key:               key,
		codes:             map[string]mockAuthCode{},
		Sub:               "mock-sub-1",
		PreferredUsername: "mockuser",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/authorize", m.handleAuthorize)
	mux.HandleFunc("/token", m.handleToken)
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockOIDCServer) issuer() string { return m.server.URL }

func (m *mockOIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                m.issuer(),
		"authorization_endpoint":                m.issuer() + "/authorize",
		"token_endpoint":                        m.issuer() + "/token",
		"jwks_uri":                              m.issuer() + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (m *mockOIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	pub := m.key.Public().(*rsa.PublicKey)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": "test-key",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// handleAuthorize immediately "authenticates" and redirects back with a code.
func (m *mockOIDCServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	m.mu.Lock()
	m.codes[code] = mockAuthCode{nonce: q.Get("nonce"), redirectURI: q.Get("redirect_uri")}
	m.mu.Unlock()

	redirect, err := url.Parse(q.Get("redirect_uri"))
	require.NoError(m.t, err)
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (m *mockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	require.NoError(m.t, r.ParseForm())
	code := r.Form.Get("code")
	m.mu.Lock()
	authCode, ok := m.codes[code]
	delete(m.codes, code)
	m.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	clientID, _, _ := r.BasicAuth()
	if clientID == "" {
		clientID = r.Form.Get("client_id")
	}

	now := time.Now()
	claims := map[string]any{
		"iss":                m.issuer(),
		"sub":                m.Sub,
		"aud":                clientID,
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"nonce":              authCode.nonce,
		"preferred_username": m.PreferredUsername,
	}
	idToken := m.signJWT(claims)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (m *mockOIDCServer) signJWT(claims map[string]any) string {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, digest[:])
	require.NoError(m.t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
