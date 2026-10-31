package goauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softAuthenticator is a minimal software passkey (ES256, "none"
// attestation, resident key) driving real WebAuthn ceremonies in tests.
type softAuthenticator struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	signCount  uint32
	origin     string
}

func newSoftAuthenticator(t *testing.T, origin string) *softAuthenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(t, err)
	return &softAuthenticator{t: t, key: key, credID: credID, origin: origin}
}

func (s *softAuthenticator) clientData(ceremony, challenge string) []byte {
	raw, err := json.Marshal(map[string]string{
		"type":      ceremony,
		"challenge": challenge,
		"origin":    s.origin,
	})
	require.NoError(s.t, err)
	return raw
}

func (s *softAuthenticator) cosePublicKey() []byte {
	x := s.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := s.key.PublicKey.Y.FillBytes(make([]byte, 32))
	coseKey := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	}
	raw, err := cbor.Marshal(coseKey)
	require.NoError(s.t, err)
	return raw
}

func (s *softAuthenticator) authData(rpID string, attested bool) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	flags := byte(0x01 | 0x04) // UP | UV
	if attested {
		flags |= 0x40 // AT
	}
	data := append([]byte{}, rpIDHash[:]...)
	data = append(data, flags)
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, s.signCount)
	data = append(data, count...)
	if attested {
		aaguid := make([]byte, 16)
		data = append(data, aaguid...)
		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(s.credID)))
		data = append(data, credIDLen...)
		data = append(data, s.credID...)
		data = append(data, s.cosePublicKey()...)
	}
	return data
}

// register performs the attestation ceremony against begin options JSON and
// returns the JSON body for the finish request.
func (s *softAuthenticator) register(beginOptions []byte) []byte {
	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	require.NoError(s.t, json.Unmarshal(beginOptions, &options))

	userHandle, err := base64.RawURLEncoding.DecodeString(options.PublicKey.User.ID)
	require.NoError(s.t, err)
	s.userHandle = userHandle

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": s.authData(options.PublicKey.RP.ID, true),
	})
	require.NoError(s.t, err)

	body, err := json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(s.credID),
		"rawId": base64.RawURLEncoding.EncodeToString(s.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(s.clientData("webauthn.create", options.PublicKey.Challenge)),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObj),
		},
		// Browsers report credProps for resident-key registrations whether or
		// not the RP asked for it.
		"clientExtensionResults": map[string]any{
			"credProps": map[string]any{"rk": true},
		},
	})
	require.NoError(s.t, err)
	return body
}

// assert performs the assertion ceremony against begin options JSON and
// returns the JSON body for the finish request.
func (s *softAuthenticator) assert(beginOptions []byte) []byte {
	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RPID      string `json:"rpId"`
		} `json:"publicKey"`
	}
	require.NoError(s.t, json.Unmarshal(beginOptions, &options))

	s.signCount++
	authData := s.authData(options.PublicKey.RPID, false)
	clientData := s.clientData("webauthn.get", options.PublicKey.Challenge)
	clientDataHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	require.NoError(s.t, err)

	body, err := json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(s.credID),
		"rawId": base64.RawURLEncoding.EncodeToString(s.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
			"userHandle":        base64.RawURLEncoding.EncodeToString(s.userHandle),
		},
		// An output the RP never requested, as some passkey managers send.
		"clientExtensionResults": map[string]any{
			"unrequestedExample": true,
		},
	})
	require.NoError(s.t, err)
	return body
}

// rawPost sends a raw JSON body and returns status + body bytes.
func (env *testEnv) rawPost(client *http.Client, path string, body []byte) (int, []byte) {
	env.t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.url(path), bytes.NewReader(body))
	require.NoError(env.t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(env.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(env.t, err)
	return resp.StatusCode, raw
}

func TestPasskeyRegistrationAndLogin(t *testing.T) {
	env := newTestEnv(t, nil)
	authenticator := newSoftAuthenticator(t, env.server.URL)

	// Register a passkey while logged in with a password.
	client := env.adminClient()
	status, beginBody := env.rawPost(client, "/auth/passkey/register/begin", nil)
	require.Equal(t, http.StatusOK, status, "begin body: %s", beginBody)

	finishBody := authenticator.register(beginBody)
	status, respBody := env.rawPost(client, "/auth/passkey/register/finish?name=test-key", finishBody)
	require.Equal(t, http.StatusCreated, status, "finish body: %s", respBody)

	var created passkeyDTO
	require.NoError(t, json.Unmarshal(respBody, &created))
	assert.Equal(t, "test-key", created.Name)

	// The passkey shows up in the credential list.
	var passkeys []passkeyDTO
	resp := env.doJSON(client, http.MethodGet, "/auth/passkeys", nil, &passkeys)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, passkeys, 1)
	assert.Nil(t, passkeys[0].LastUsedAt)

	// Log in from a fresh "browser" using only the passkey.
	fresh := env.client()
	status, loginBegin := env.rawPost(fresh, "/auth/passkey/login/begin", nil)
	require.Equal(t, http.StatusOK, status, "login begin: %s", loginBegin)

	assertion := authenticator.assert(loginBegin)
	status, loginResp := env.rawPost(fresh, "/auth/passkey/login/finish", assertion)
	require.Equal(t, http.StatusOK, status, "login finish: %s", loginResp)

	var user UserDTO
	require.NoError(t, json.Unmarshal(loginResp, &user))
	assert.Equal(t, "admin", user.Username)

	// Session is live and last-used got stamped.
	resp = env.doJSON(fresh, http.MethodGet, "/auth/me", nil, &user)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	env.doJSON(client, http.MethodGet, "/auth/passkeys", nil, &passkeys)
	require.Len(t, passkeys, 1)
	assert.NotNil(t, passkeys[0].LastUsedAt)

	// Deleting the passkey stops future logins.
	resp = env.doJSON(client, http.MethodDelete, fmt.Sprintf("/auth/passkeys/%d", passkeys[0].ID), nil, nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	third := env.client()
	status, loginBegin = env.rawPost(third, "/auth/passkey/login/begin", nil)
	require.Equal(t, http.StatusOK, status)
	assertion = authenticator.assert(loginBegin)
	status, _ = env.rawPost(third, "/auth/passkey/login/finish", assertion)
	assert.Equal(t, http.StatusUnauthorized, status)
}

func TestPasskeyLoginTamperedSignature(t *testing.T) {
	env := newTestEnv(t, nil)
	authenticator := newSoftAuthenticator(t, env.server.URL)

	client := env.adminClient()
	_, beginBody := env.rawPost(client, "/auth/passkey/register/begin", nil)
	finishBody := authenticator.register(beginBody)
	status, _ := env.rawPost(client, "/auth/passkey/register/finish", finishBody)
	require.Equal(t, http.StatusCreated, status)

	// Sign with a different key: login must fail.
	rogue := newSoftAuthenticator(t, env.server.URL)
	rogue.credID = authenticator.credID
	rogue.userHandle = authenticator.userHandle

	fresh := env.client()
	status, loginBegin := env.rawPost(fresh, "/auth/passkey/login/begin", nil)
	require.Equal(t, http.StatusOK, status)
	assertion := rogue.assert(loginBegin)
	status, _ = env.rawPost(fresh, "/auth/passkey/login/finish", assertion)
	assert.Equal(t, http.StatusUnauthorized, status)

	resp := env.doJSON(fresh, http.MethodGet, "/auth/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestPasskeysDisabledWithoutRPID(t *testing.T) {
	env := newTestEnv(t, func(cfg *Config) { cfg.RPID = "" })
	client := env.client()
	status, _ := env.rawPost(client, "/auth/passkey/login/begin", nil)
	assert.Equal(t, http.StatusNotImplemented, status)

	var cfg authConfigDTO
	env.doJSON(client, http.MethodGet, "/auth/config", nil, &cfg)
	assert.False(t, cfg.Passkeys)
}
