package goauth

import (
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
)

type oidcProviderAdminDTO struct {
	ID              uint      `json:"id"`
	Name            string    `json:"name"`
	IssuerURL       string    `json:"issuerUrl"`
	ClientID        string    `json:"clientId"`
	HasClientSecret bool      `json:"hasClientSecret"`
	Scopes          string    `json:"scopes"`
	AutoProvision   bool      `json:"autoProvision"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"createdAt"`
}

func toOIDCProviderAdminDTO(p *OIDCProvider) oidcProviderAdminDTO {
	return oidcProviderAdminDTO{
		ID:              p.ID,
		Name:            p.Name,
		IssuerURL:       p.IssuerURL,
		ClientID:        p.ClientID,
		HasClientSecret: p.ClientSecret != "",
		Scopes:          p.Scopes,
		AutoProvision:   p.AutoProvision,
		Enabled:         p.Enabled,
		CreatedAt:       p.CreatedAt,
	}
}

func (a *Auth) registerAdminRoutes(g *echo.Group) {
	g.GET("/users", a.handleAdminListUsers)
	g.POST("/users", a.handleAdminCreateUser)
	g.PATCH("/users/:id", a.handleAdminUpdateUser)
	g.DELETE("/users/:id", a.handleAdminDeleteUser)

	g.GET("/oidc", a.handleAdminListOIDCProviders)
	g.POST("/oidc", a.handleAdminCreateOIDCProvider)
	g.PATCH("/oidc/:id", a.handleAdminUpdateOIDCProvider)
	g.DELETE("/oidc/:id", a.handleAdminDeleteOIDCProvider)

	g.GET("/settings", a.handleAdminGetSettings)
	g.PUT("/settings", a.handleAdminUpdateSettings)
}

func paramID(c echo.Context) (uint, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		return 0, echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	return uint(id), nil
}

// --- Users ---

func (a *Auth) handleAdminListUsers(c echo.Context) error {
	users, err := a.ListUsers()
	if err != nil {
		return err
	}
	dtos := make([]UserDTO, 0, len(users))
	for i := range users {
		dtos = append(dtos, toUserDTO(&users[i]))
	}
	return c.JSON(http.StatusOK, dtos)
}

type adminCreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     Role   `json:"role"`
}

func (a *Auth) handleAdminCreateUser(c echo.Context) error {
	var req adminCreateUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.Role == "" {
		req.Role = RoleUser
	}
	user, err := a.CreateUser(req.Username, req.Password, req.Email, req.Role)
	if err != nil {
		return mapServiceError(err)
	}
	return c.JSON(http.StatusCreated, toUserDTO(user))
}

type adminUpdateUserRequest struct {
	Username *string `json:"username"`
	Email    *string `json:"email"`
	Role     *Role   `json:"role"`
	Disabled *bool   `json:"disabled"`
	Password *string `json:"password"`
}

func (a *Auth) handleAdminUpdateUser(c echo.Context) error {
	id, err := paramID(c)
	if err != nil {
		return err
	}
	var req adminUpdateUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	user, err := a.UpdateUser(id, UserPatch{
		Username: req.Username,
		Email:    req.Email,
		Role:     req.Role,
		Disabled: req.Disabled,
		Password: req.Password,
	})
	if err != nil {
		return mapServiceError(err)
	}
	return c.JSON(http.StatusOK, toUserDTO(user))
}

func (a *Auth) handleAdminDeleteUser(c echo.Context) error {
	id, err := paramID(c)
	if err != nil {
		return err
	}
	if current := CurrentUser(c); current != nil && current.ID == id {
		return echo.NewHTTPError(http.StatusBadRequest, "cannot delete your own account")
	}
	if err := a.DeleteUser(id); err != nil {
		return mapServiceError(err)
	}
	return c.NoContent(http.StatusNoContent)
}

// --- OIDC providers ---

// ListOIDCProviders returns providers, optionally only enabled ones.
func (a *Auth) ListOIDCProviders(enabledOnly bool) ([]OIDCProvider, error) {
	var providers []OIDCProvider
	q := a.db.Order("id asc")
	if enabledOnly {
		q = q.Where("enabled = ?", true)
	}
	err := q.Find(&providers).Error
	return providers, err
}

func (a *Auth) handleAdminListOIDCProviders(c echo.Context) error {
	providers, err := a.ListOIDCProviders(false)
	if err != nil {
		return err
	}
	dtos := make([]oidcProviderAdminDTO, 0, len(providers))
	for i := range providers {
		dtos = append(dtos, toOIDCProviderAdminDTO(&providers[i]))
	}
	return c.JSON(http.StatusOK, dtos)
}

type adminOIDCProviderRequest struct {
	Name          *string `json:"name"`
	IssuerURL     *string `json:"issuerUrl"`
	ClientID      *string `json:"clientId"`
	ClientSecret  *string `json:"clientSecret"`
	Scopes        *string `json:"scopes"`
	AutoProvision *bool   `json:"autoProvision"`
	Enabled       *bool   `json:"enabled"`
}

func (a *Auth) handleAdminCreateOIDCProvider(c echo.Context) error {
	var req adminOIDCProviderRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	provider := OIDCProvider{AutoProvision: true, Enabled: true}
	applyOIDCProviderPatch(&provider, req)
	if provider.Name == "" || provider.IssuerURL == "" || provider.ClientID == "" || provider.ClientSecret == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, issuerUrl, clientId and clientSecret are required")
	}
	if err := a.db.Create(&provider).Error; err != nil {
		return err
	}
	a.oidc.invalidate(provider.ID)
	return c.JSON(http.StatusCreated, toOIDCProviderAdminDTO(&provider))
}

func (a *Auth) handleAdminUpdateOIDCProvider(c echo.Context) error {
	id, err := paramID(c)
	if err != nil {
		return err
	}
	var req adminOIDCProviderRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	provider, err := a.findOIDCProvider(id)
	if err != nil {
		return mapServiceError(err)
	}

	disabling := req.Enabled != nil && !*req.Enabled && provider.Enabled
	if disabling {
		if err := a.ensureNotLastEnabledProvider(provider.ID); err != nil {
			return mapServiceError(err)
		}
	}

	applyOIDCProviderPatch(provider, req)
	if err := a.db.Save(provider).Error; err != nil {
		return err
	}
	a.oidc.invalidate(provider.ID)
	return c.JSON(http.StatusOK, toOIDCProviderAdminDTO(provider))
}

func (a *Auth) handleAdminDeleteOIDCProvider(c echo.Context) error {
	id, err := paramID(c)
	if err != nil {
		return err
	}
	provider, err := a.findOIDCProvider(id)
	if err != nil {
		return mapServiceError(err)
	}
	if provider.Enabled {
		if err := a.ensureNotLastEnabledProvider(provider.ID); err != nil {
			return mapServiceError(err)
		}
	}
	if err := a.db.Delete(&OIDCProvider{}, id).Error; err != nil {
		return err
	}
	a.oidc.invalidate(id)
	return c.NoContent(http.StatusNoContent)
}

func applyOIDCProviderPatch(p *OIDCProvider, req adminOIDCProviderRequest) {
	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.IssuerURL != nil {
		p.IssuerURL = *req.IssuerURL
	}
	if req.ClientID != nil {
		p.ClientID = *req.ClientID
	}
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		p.ClientSecret = *req.ClientSecret
	}
	if req.Scopes != nil {
		p.Scopes = *req.Scopes
	}
	if req.AutoProvision != nil {
		p.AutoProvision = *req.AutoProvision
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
}

func (a *Auth) findOIDCProvider(id uint) (*OIDCProvider, error) {
	var provider OIDCProvider
	if err := a.db.First(&provider, id).Error; err != nil {
		return nil, ErrNotFound
	}
	return &provider, nil
}

// ensureNotLastEnabledProvider blocks disabling/deleting the final enabled
// provider while an OIDC mode depends on it.
func (a *Auth) ensureNotLastEnabledProvider(providerID uint) error {
	settings, err := a.GetSettings()
	if err != nil {
		return err
	}
	if settings.OIDCMode == OIDCModeDisabled {
		return nil
	}
	var others int64
	if err := a.db.Model(&OIDCProvider{}).Where("enabled = ? AND id <> ?", true, providerID).Count(&others).Error; err != nil {
		return err
	}
	if others == 0 {
		return ErrInvalidInput("cannot remove the last enabled provider while OIDC mode is active; set mode to disabled first")
	}
	return nil
}

// --- Settings ---

type settingsDTO struct {
	OIDCMode OIDCMode `json:"oidcMode"`
}

func (a *Auth) handleAdminGetSettings(c echo.Context) error {
	settings, err := a.GetSettings()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, settingsDTO{OIDCMode: settings.OIDCMode})
}

func (a *Auth) handleAdminUpdateSettings(c echo.Context) error {
	var req settingsDTO
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	settings, err := a.UpdateSettings(req.OIDCMode)
	if err != nil {
		return mapServiceError(err)
	}
	return c.JSON(http.StatusOK, settingsDTO{OIDCMode: settings.OIDCMode})
}
