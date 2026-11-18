package goauth

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RegisterAvatarRoutes mounts self-service routes at me's prefix and the admin
// read at admin's prefix + /users/:id/avatar. Callers must apply SessionMiddleware,
// RequireAuthenticated on me and RequireRole(RoleAdmin) on admin.
func (a *Auth) RegisterAvatarRoutes(me, admin *echo.Group) {
	me.PUT("", a.UploadAvatar)
	me.GET("", a.Avatar)
	me.DELETE("", a.DeleteAvatar)
	admin.GET("/users/:id/avatar", a.UserAvatar)
}

// UploadAvatar replaces the current user's avatar from multipart field file.
func (a *Auth) UploadAvatar(c echo.Context) error {
	user := CurrentUser(c)
	if user == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, a.cfg.MaxAvatarBytes)
	defer func() {
		if form := c.Request().MultipartForm; form != nil {
			_ = form.RemoveAll()
		}
	}()
	file, err := c.FormFile("file")
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "avatar upload too large")
		}
		return echo.NewHTTPError(http.StatusBadRequest, "file is required")
	}
	src, err := file.Open()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to read upload").SetInternal(err)
	}
	defer src.Close()
	data, err := io.ReadAll(src)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to read upload").SetInternal(err)
	}
	contentType := http.DetectContentType(data)
	if len(data) == 0 || !strings.HasPrefix(contentType, "image/") {
		return echo.NewHTTPError(http.StatusBadRequest, "not an image")
	}
	err = a.db.Transaction(func(tx *gorm.DB) error {
		avatar := UserAvatar{UserID: user.ID, ContentType: contentType, Data: data}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"content_type", "data", "updated_at"}),
		}).Create(&avatar).Error; err != nil {
			return err
		}
		return tx.Model(&User{}).Where("id = ?", user.ID).Update("updated_at", time.Now().UTC()).Error
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to store avatar").SetInternal(err)
	}
	return c.NoContent(http.StatusNoContent)
}

// Avatar serves the current user's avatar, or 204 if none exists.
func (a *Auth) Avatar(c echo.Context) error {
	user := CurrentUser(c)
	if user == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}
	return a.serveAvatar(c, user.ID)
}

// DeleteAvatar removes the current user's avatar.
func (a *Auth) DeleteAvatar(c echo.Context) error {
	user := CurrentUser(c)
	if user == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}
	err := a.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", user.ID).Delete(&UserAvatar{}).Error; err != nil {
			return err
		}
		return tx.Model(&User{}).Where("id = ?", user.ID).Update("updated_at", time.Now().UTC()).Error
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete avatar").SetInternal(err)
	}
	return c.NoContent(http.StatusNoContent)
}

// UserAvatar serves the avatar identified by :id. Callers must require admin role.
func (a *Auth) UserAvatar(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}
	return a.serveAvatar(c, uint(id))
}

func (a *Auth) serveAvatar(c echo.Context, userID uint) error {
	var avatar UserAvatar
	err := a.db.First(&avatar, "user_id = ?", userID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return c.NoContent(http.StatusNoContent)
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to load avatar").SetInternal(err)
	}
	c.Response().Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	return c.Blob(http.StatusOK, avatar.ContentType, avatar.Data)
}
