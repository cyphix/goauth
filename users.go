package goauth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/alexedwards/argon2id"
	"gorm.io/gorm"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$`)

// NormalizeUsername lowercases and trims a username.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func validateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return ErrInvalidInput("username must be 3-64 chars of a-z, 0-9, '.', '_' or '-' and start/end alphanumeric")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return ErrInvalidInput("password must be at least 8 characters")
	}
	if len(password) > 512 {
		return ErrInvalidInput("password must be at most 512 characters")
	}
	return nil
}

func hashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

// CreateUser creates a new local user. Password may be empty for accounts
// that only log in via passkey or OIDC.
func (a *Auth) CreateUser(username, password string, role Role) (*User, error) {
	username = NormalizeUsername(username)
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if !ValidRole(role) {
		return nil, ErrInvalidInput("unknown role")
	}

	var existing int64
	if err := a.db.Model(&User{}).Where("username = ?", username).Count(&existing).Error; err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, ErrInvalidInput(fmt.Sprintf("username %q is already taken", username))
	}

	user := &User{Username: username, Role: role}
	if password != "" {
		if err := validatePassword(password); err != nil {
			return nil, err
		}
		hash, err := hashPassword(password)
		if err != nil {
			return nil, err
		}
		user.PasswordHash = &hash
	}
	if err := a.db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// EnsureUser creates the user when it does not exist yet; useful for seeding.
// Existing users are returned unchanged.
func (a *Auth) EnsureUser(username, password string, role Role) (*User, error) {
	username = NormalizeUsername(username)
	user, err := a.FindUserByUsername(username)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return a.CreateUser(username, password, role)
}

// FindUserByID loads a user by primary key.
func (a *Auth) FindUserByID(id uint) (*User, error) {
	var user User
	if err := a.db.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindUserByUsername loads a user by normalized username.
func (a *Auth) FindUserByUsername(username string) (*User, error) {
	var user User
	err := a.db.Where("username = ?", NormalizeUsername(username)).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// ListUsers returns all users ordered by username.
func (a *Auth) ListUsers() ([]User, error) {
	var users []User
	err := a.db.Preload("Credentials").Order("username asc").Find(&users).Error
	return users, err
}

// Authenticate verifies username+password and returns the user. Disabled
// accounts and accounts without a password fail with ErrInvalidCredentials.
func (a *Auth) Authenticate(username, password string) (*User, error) {
	user, err := a.FindUserByUsername(username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if user.Disabled || !user.HasPassword() {
		return nil, ErrInvalidCredentials
	}
	match, err := argon2id.ComparePasswordAndHash(password, *user.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, ErrInvalidCredentials
	}
	return user, nil
}

// SetPassword replaces the user's password (admin reset or self change).
func (a *Auth) SetPassword(userID uint, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return a.db.Model(&User{}).Where("id = ?", userID).Update("password_hash", hash).Error
}

// ChangePassword verifies the current password before setting a new one.
func (a *Auth) ChangePassword(userID uint, currentPassword, newPassword string) error {
	user, err := a.FindUserByID(userID)
	if err != nil {
		return err
	}
	if !user.HasPassword() {
		return ErrInvalidInput("account has no password set")
	}
	match, err := argon2id.ComparePasswordAndHash(currentPassword, *user.PasswordHash)
	if err != nil {
		return err
	}
	if !match {
		return ErrInvalidCredentials
	}
	return a.SetPassword(userID, newPassword)
}

// UserPatch is a partial admin update of a user.
type UserPatch struct {
	Role     *Role
	Disabled *bool
	Password *string
}

// UpdateUser applies an admin patch, protecting the last active admin from
// demotion or disabling.
func (a *Auth) UpdateUser(id uint, patch UserPatch) (*User, error) {
	user, err := a.FindUserByID(id)
	if err != nil {
		return nil, err
	}

	demoting := patch.Role != nil && *patch.Role != RoleAdmin && user.Role == RoleAdmin
	disabling := patch.Disabled != nil && *patch.Disabled && !user.Disabled
	if user.Role == RoleAdmin && (demoting || disabling) {
		lastAdmin, err := a.isLastActiveAdmin(user.ID)
		if err != nil {
			return nil, err
		}
		if lastAdmin {
			return nil, ErrInvalidInput("cannot demote or disable the last active admin")
		}
	}

	updates := map[string]any{}
	if patch.Role != nil {
		if !ValidRole(*patch.Role) {
			return nil, ErrInvalidInput("unknown role")
		}
		updates["role"] = *patch.Role
	}
	if patch.Disabled != nil {
		updates["disabled"] = *patch.Disabled
	}
	if patch.Password != nil {
		if err := validatePassword(*patch.Password); err != nil {
			return nil, err
		}
		hash, err := hashPassword(*patch.Password)
		if err != nil {
			return nil, err
		}
		updates["password_hash"] = hash
	}
	if len(updates) > 0 {
		if err := a.db.Model(user).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	return a.FindUserByID(id)
}

// DeleteUser soft-deletes a user, protecting the last active admin.
func (a *Auth) DeleteUser(id uint) error {
	user, err := a.FindUserByID(id)
	if err != nil {
		return err
	}
	if user.Role == RoleAdmin {
		lastAdmin, err := a.isLastActiveAdmin(user.ID)
		if err != nil {
			return err
		}
		if lastAdmin {
			return ErrInvalidInput("cannot delete the last active admin")
		}
	}
	return a.db.Delete(&User{}, id).Error
}

func (a *Auth) isLastActiveAdmin(userID uint) (bool, error) {
	var others int64
	err := a.db.Model(&User{}).
		Where("role = ? AND disabled = ? AND id <> ?", RoleAdmin, false, userID).
		Count(&others).Error
	if err != nil {
		return false, err
	}
	return others == 0, nil
}
