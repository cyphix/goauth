package goauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
)

const (
	sessionKeyWebauthnRegistration = "goauth_webauthn_registration"
	sessionKeyWebauthnLogin        = "goauth_webauthn_login"
)

// webauthnUser adapts User to the webauthn.User interface. The WebAuthn user
// handle is the decimal user ID.
type webauthnUser struct {
	user  *User
	creds []webauthn.Credential
}

func (w *webauthnUser) WebAuthnID() []byte          { return []byte(strconv.FormatUint(uint64(w.user.ID), 10)) }
func (w *webauthnUser) WebAuthnName() string        { return w.user.Username }
func (w *webauthnUser) WebAuthnDisplayName() string { return w.user.Username }
func (w *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return w.creds
}

// loadWebauthnUser loads the user's stored passkeys as webauthn credentials.
func (a *Auth) loadWebauthnUser(user *User) (*webauthnUser, []WebauthnCredential, error) {
	var rows []WebauthnCredential
	if err := a.db.Where("user_id = ?", user.ID).Order("id asc").Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for i := range rows {
		var cred webauthn.Credential
		if err := json.Unmarshal(rows[i].Credential, &cred); err != nil {
			a.logger.Error().Err(err).Uint("credential", rows[i].ID).Msg("corrupt stored webauthn credential")
			continue
		}
		creds = append(creds, cred)
	}
	return &webauthnUser{user: user, creds: creds}, rows, nil
}

func (a *Auth) registerPasskeyRoutes(g *echo.Group, authed *echo.Group) {
	g.POST("/passkey/login/begin", a.handlePasskeyLoginBegin)
	g.POST("/passkey/login/finish", a.handlePasskeyLoginFinish)

	authed.POST("/passkey/register/begin", a.handlePasskeyRegisterBegin)
	authed.POST("/passkey/register/finish", a.handlePasskeyRegisterFinish)
	authed.GET("/passkeys", a.handleListPasskeys)
	authed.DELETE("/passkeys/:id", a.handleDeletePasskey)
}

func (a *Auth) requirePasskeys() error {
	if !a.PasskeysEnabled() {
		return echo.NewHTTPError(http.StatusNotImplemented, "passkeys are not configured (missing RPID)")
	}
	return nil
}

func (a *Auth) storeWebauthnSession(c echo.Context, key string, data *webauthn.SessionData) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	a.sessions.Put(c.Request().Context(), key, string(raw))
	return nil
}

func (a *Auth) popWebauthnSession(c echo.Context, key string) (*webauthn.SessionData, error) {
	raw := a.sessions.PopString(c.Request().Context(), key)
	if raw == "" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "no pending passkey ceremony")
	}
	var data webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// --- Registration (authenticated) ---

func (a *Auth) handlePasskeyRegisterBegin(c echo.Context) error {
	if err := a.requirePasskeys(); err != nil {
		return err
	}
	user := CurrentUser(c)
	waUser, rows, err := a.loadWebauthnUser(user)
	if err != nil {
		return err
	}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(rows))
	for _, cred := range waUser.creds {
		exclusions = append(exclusions, cred.Descriptor())
	}

	options, sessionData, err := a.webauthn.BeginRegistration(
		waUser,
		webauthn.WithExclusions(exclusions),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		return err
	}
	if err := a.storeWebauthnSession(c, sessionKeyWebauthnRegistration, sessionData); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, options)
}

func (a *Auth) handlePasskeyRegisterFinish(c echo.Context) error {
	if err := a.requirePasskeys(); err != nil {
		return err
	}
	user := CurrentUser(c)
	sessionData, err := a.popWebauthnSession(c, sessionKeyWebauthnRegistration)
	if err != nil {
		return err
	}
	waUser, _, err := a.loadWebauthnUser(user)
	if err != nil {
		return err
	}

	credential, err := a.webauthn.FinishRegistration(waUser, *sessionData, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "passkey registration failed: "+err.Error())
	}

	name := c.QueryParam("name")
	if name == "" {
		name = "Passkey " + time.Now().UTC().Format("2006-01-02")
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	row := WebauthnCredential{
		UserID:       user.ID,
		Name:         name,
		CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID),
		Credential:   raw,
	}
	if err := a.db.Create(&row).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, toPasskeyDTO(&row))
}

// --- Login (public, discoverable) ---

func (a *Auth) handlePasskeyLoginBegin(c echo.Context) error {
	if err := a.requirePasskeys(); err != nil {
		return err
	}
	if err := a.rejectWhenOIDCRequired(); err != nil {
		return err
	}
	options, sessionData, err := a.webauthn.BeginDiscoverableLogin()
	if err != nil {
		return err
	}
	if err := a.storeWebauthnSession(c, sessionKeyWebauthnLogin, sessionData); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, options)
}

func (a *Auth) handlePasskeyLoginFinish(c echo.Context) error {
	if err := a.requirePasskeys(); err != nil {
		return err
	}
	if err := a.rejectWhenOIDCRequired(); err != nil {
		return err
	}
	sessionData, err := a.popWebauthnSession(c, sessionKeyWebauthnLogin)
	if err != nil {
		return err
	}

	var loggedIn *User
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		id, err := strconv.ParseUint(string(userHandle), 10, 32)
		if err != nil {
			return nil, protocol.ErrBadRequest.WithDetails("unknown user handle")
		}
		user, err := a.FindUserByID(uint(id))
		if err != nil || user.Disabled {
			return nil, protocol.ErrBadRequest.WithDetails("unknown or disabled user")
		}
		waUser, _, err := a.loadWebauthnUser(user)
		if err != nil {
			return nil, err
		}
		loggedIn = user
		return waUser, nil
	}

	credential, err := a.webauthn.FinishDiscoverableLogin(handler, *sessionData, c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "passkey login failed")
	}
	if credential.Authenticator.CloneWarning {
		return echo.NewHTTPError(http.StatusUnauthorized, "passkey login failed (clone warning)")
	}

	if err := a.touchCredential(credential); err != nil {
		return err
	}
	if err := a.createSession(c, loggedIn); err != nil {
		return err
	}
	a.attachUser(c, loggedIn)
	return c.JSON(http.StatusOK, toUserDTO(loggedIn))
}

// touchCredential persists the updated sign counter and last-used timestamp.
func (a *Auth) touchCredential(credential *webauthn.Credential) error {
	raw, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return a.db.Model(&WebauthnCredential{}).
		Where("credential_id = ?", base64.RawURLEncoding.EncodeToString(credential.ID)).
		Updates(map[string]any{"credential": raw, "last_used_at": now}).Error
}

// --- Credential management (authenticated) ---

type passkeyDTO struct {
	ID         uint       `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

func toPasskeyDTO(row *WebauthnCredential) passkeyDTO {
	return passkeyDTO{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt, LastUsedAt: row.LastUsedAt}
}

func (a *Auth) handleListPasskeys(c echo.Context) error {
	user := CurrentUser(c)
	var rows []WebauthnCredential
	if err := a.db.Where("user_id = ?", user.ID).Order("id asc").Find(&rows).Error; err != nil {
		return err
	}
	dtos := make([]passkeyDTO, 0, len(rows))
	for i := range rows {
		dtos = append(dtos, toPasskeyDTO(&rows[i]))
	}
	return c.JSON(http.StatusOK, dtos)
}

func (a *Auth) handleDeletePasskey(c echo.Context) error {
	user := CurrentUser(c)
	id, err := paramID(c)
	if err != nil {
		return err
	}
	res := a.db.Where("id = ? AND user_id = ?", id, user.ID).Delete(&WebauthnCredential{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "passkey not found")
	}
	return c.NoContent(http.StatusNoContent)
}
