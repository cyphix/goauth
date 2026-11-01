package goauth

import (
	"errors"
	"fmt"
	"net/mail"
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

// NormalizeEmail lowercases and trims an email address.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateEmail(email string) error {
	if len(email) > 254 {
		return ErrInvalidInput("email must be at most 254 characters")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return ErrInvalidInput("invalid email address")
	}
	return nil
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

// CreateUser creates a new local user. Password and email may be empty for
// accounts that only log in via passkey or OIDC.
func (a *Auth) CreateUser(username, password, email string, role Role) (*User, error) {
	username = NormalizeUsername(username)
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if !ValidRole(role) {
		return nil, ErrInvalidInput("unknown role")
	}
	email = NormalizeEmail(email)
	if email != "" {
		if err := validateEmail(email); err != nil {
			return nil, err
		}
	}

	if err := a.ensureUsernameFree(username, 0); err != nil {
		return nil, err
	}
	if email != "" {
		if err := a.ensureEmailFree(email, 0); err != nil {
			return nil, err
		}
	}

	user := &User{Username: username, Role: role}
	if email != "" {
		user.Email = &email
	}
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
	return a.CreateUser(username, password, "", role)
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

// FindUserByIdentifier loads a user by login identifier: username or email.
func (a *Auth) FindUserByIdentifier(identifier string) (*User, error) {
	var user User
	norm := NormalizeUsername(identifier)
	err := a.db.Where("username = ? OR email = ?", norm, norm).First(&user).Error
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

// Authenticate verifies identifier+password and returns the user. The
// identifier may be the username or the account email. Disabled accounts and
// accounts without a password fail with ErrInvalidCredentials.
func (a *Auth) Authenticate(identifier, password string) (*User, error) {
	user, err := a.FindUserByIdentifier(identifier)
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
// Passwordless non-OIDC accounts may set an initial password via their session.
func (a *Auth) ChangePassword(userID uint, currentPassword, newPassword string) error {
	user, err := a.FindUserByID(userID)
	if err != nil {
		return err
	}
	if !user.HasPassword() {
		if user.OIDCSub != nil {
			return ErrPasswordManagedByIdP
		}
		return a.SetPassword(userID, newPassword)
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

// ProfilePatch is a partial self-service update of the caller's profile.
type ProfilePatch struct {
	Username *string
	Email    *string
}

// UpdateProfile applies a self-service profile patch.
func (a *Auth) UpdateProfile(userID uint, patch ProfilePatch) (*User, error) {
	user, err := a.FindUserByID(userID)
	if err != nil {
		return nil, err
	}
	updates, err := a.profileUpdates(user, patch.Username, patch.Email)
	if err != nil {
		return nil, err
	}
	if len(updates) > 0 {
		if err := a.db.Model(user).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	return a.findUserFull(userID)
}

// UserPatch is a partial admin update of a user.
type UserPatch struct {
	Username *string
	Email    *string
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

	updates, err := a.profileUpdates(user, patch.Username, patch.Email)
	if err != nil {
		return nil, err
	}
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
	return a.findUserFull(id)
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

// profileUpdates validates username/email patches and returns the changed
// columns, skipping values identical to the current ones.
func (a *Auth) profileUpdates(user *User, username, email *string) (map[string]any, error) {
	updates := map[string]any{}
	if username != nil {
		name := NormalizeUsername(*username)
		if err := validateUsername(name); err != nil {
			return nil, err
		}
		if name != user.Username {
			if err := a.ensureUsernameFree(name, user.ID); err != nil {
				return nil, err
			}
			updates["username"] = name
		}
	}
	if email != nil {
		addr := NormalizeEmail(*email)
		current := ""
		if user.Email != nil {
			current = *user.Email
		}
		if addr != current {
			if addr == "" {
				updates["email"] = nil
			} else {
				if err := validateEmail(addr); err != nil {
					return nil, err
				}
				if err := a.ensureEmailFree(addr, user.ID); err != nil {
					return nil, err
				}
				updates["email"] = addr
			}
		}
	}
	return updates, nil
}

// findUserFull reloads a user with its passkey credentials so DTOs report a
// correct passkey count.
func (a *Auth) findUserFull(id uint) (*User, error) {
	var user User
	if err := a.db.Preload("Credentials").First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// ensureUsernameFree fails when another active user already holds username.
func (a *Auth) ensureUsernameFree(username string, excludeID uint) error {
	var count int64
	if err := a.db.Model(&User{}).
		Where("username = ? AND id <> ?", username, excludeID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrInvalidInput(fmt.Sprintf("username %q is already taken", username))
	}
	return nil
}

// ensureEmailFree fails when another active user already holds email.
func (a *Auth) ensureEmailFree(email string, excludeID uint) error {
	var count int64
	if err := a.db.Model(&User{}).
		Where("email = ? AND id <> ?", email, excludeID).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return ErrInvalidInput("email is already in use")
	}
	return nil
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
