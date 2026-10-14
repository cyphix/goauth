package goauth

import (
	"time"

	"gorm.io/gorm"
)

// Role is the authorization role of a user.
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// ValidRole reports whether r is a known role.
func ValidRole(r Role) bool {
	return r == RoleUser || r == RoleAdmin
}

// OIDCMode controls how OIDC participates in login.
type OIDCMode string

const (
	// OIDCModeDisabled: local login only (password + passkey).
	OIDCModeDisabled OIDCMode = "disabled"
	// OIDCModeOptional: local login stays fully usable; enabled OIDC
	// providers are listed as additional buttons on the login page.
	OIDCModeOptional OIDCMode = "optional"
	// OIDCModeRequired: OIDC is the default and required method; local login
	// is bypassed and password/passkey endpoints are rejected.
	OIDCModeRequired OIDCMode = "required"
)

// ValidOIDCMode reports whether m is a known mode.
func ValidOIDCMode(m OIDCMode) bool {
	return m == OIDCModeDisabled || m == OIDCModeOptional || m == OIDCModeRequired
}

// User is an account managed by goauth.
type User struct {
	gorm.Model
	Username     string  `gorm:"uniqueIndex:idx_auth_users_username_active,where:deleted_at IS NULL;not null"`
	// Email is an optional, normalized login identifier. NULL means unset;
	// uniqueness holds among active users only.
	Email        *string `gorm:"uniqueIndex:idx_auth_users_email_active,where:deleted_at IS NULL"`
	PasswordHash *string `gorm:"type:text"`
	Role         Role    `gorm:"type:varchar(16);not null;default:user"`
	Disabled     bool    `gorm:"not null;default:false"`

	// OIDC identity link (set when the account was provisioned by or linked
	// to an OIDC provider).
	OIDCProviderID *uint   `gorm:"column:oidc_provider_id;index"`
	OIDCSub        *string `gorm:"column:oidc_sub;index"`

	Credentials []WebauthnCredential `gorm:"foreignKey:UserID"`
}

func (User) TableName() string { return "auth_users" }

// HasPassword reports whether local password login is possible for the user.
func (u *User) HasPassword() bool { return u.PasswordHash != nil && *u.PasswordHash != "" }

// WebauthnCredential stores a registered passkey. The raw webauthn credential
// is serialized as JSON in Credential.
type WebauthnCredential struct {
	gorm.Model
	UserID       uint   `gorm:"index;not null"`
	Name         string `gorm:"not null"`
	CredentialID string `gorm:"uniqueIndex;not null"` // base64url of the credential ID
	Credential   []byte `gorm:"type:jsonb;not null"`
	LastUsedAt   *time.Time
}

func (WebauthnCredential) TableName() string { return "auth_webauthn_credentials" }

// OIDCProvider is a runtime-configurable OpenID Connect provider.
type OIDCProvider struct {
	gorm.Model
	Name         string `gorm:"not null"`
	IssuerURL    string `gorm:"not null"`
	ClientID     string `gorm:"not null"`
	ClientSecret string `gorm:"not null"`
	// Scopes are extra scopes requested in addition to "openid profile".
	Scopes string `gorm:"not null;default:''"`
	// AutoProvision creates a local account on first login for unknown
	// subjects. When false, only pre-linked users may log in.
	AutoProvision bool `gorm:"not null"`
	Enabled       bool `gorm:"not null"`
}

func (OIDCProvider) TableName() string { return "auth_oidc_providers" }

// Settings is the single-row runtime configuration.
type Settings struct {
	ID        uint     `gorm:"primarykey"`
	OIDCMode  OIDCMode `gorm:"column:oidc_mode;type:varchar(16);not null;default:disabled"`
	UpdatedAt time.Time
}

func (Settings) TableName() string { return "auth_settings" }

const settingsRowID = 1

func (a *Auth) ensureSettings() error {
	var s Settings
	err := a.db.First(&s, settingsRowID).Error
	if err == nil {
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}
	return a.db.Create(&Settings{ID: settingsRowID, OIDCMode: OIDCModeDisabled}).Error
}

// GetSettings returns the current runtime settings.
func (a *Auth) GetSettings() (Settings, error) {
	var s Settings
	err := a.db.First(&s, settingsRowID).Error
	return s, err
}

// UpdateSettings persists new runtime settings after validation.
func (a *Auth) UpdateSettings(mode OIDCMode) (Settings, error) {
	if !ValidOIDCMode(mode) {
		return Settings{}, ErrInvalidInput("unknown oidc mode")
	}
	if mode != OIDCModeDisabled {
		var enabled int64
		if err := a.db.Model(&OIDCProvider{}).Where("enabled = ?", true).Count(&enabled).Error; err != nil {
			return Settings{}, err
		}
		if enabled == 0 {
			return Settings{}, ErrInvalidInput("cannot enable oidc mode without an enabled provider")
		}
	}
	if err := a.db.Model(&Settings{}).Where("id = ?", settingsRowID).Update("oidc_mode", mode).Error; err != nil {
		return Settings{}, err
	}
	return a.GetSettings()
}
