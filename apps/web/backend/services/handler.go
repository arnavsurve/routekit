package services

import (
	"context"
	"net/http"

	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"gopkg.in/yaml.v2"
)

type ServicesHandler struct {
	DBPool *pgxpool.Pool
}

type UpdateConfigRequest struct {
	ConfigYAML string `json:"config_yaml"`
}

// HandleGetUserServices retrieves the user's current services configuration YAML
func (h *ServicesHandler) HandleGetUserServices(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var configYAML string
	err := h.DBPool.QueryRow(context.Background(), "SELECT config_yaml FROM user_service_configs WHERE user_id = $1", userID).Scan(&configYAML)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.JSON(http.StatusOK, map[string]string{"config_yaml": ""})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get user service configuration"})
	}

	return c.JSON(http.StatusOK, map[string]string{"config_yaml": configYAML})
}

// HandleUpdateUserServices saves a new service configuration YAML for the user.
func (h *ServicesHandler) HandleUpdateUserServices(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var req UpdateConfigRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request format"})
	}

	// TODO: better YAML validation
	var temp map[string]any
	if err := yaml.Unmarshal([]byte(req.ConfigYAML), &temp); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid YAML format"})
	}

	_, err := h.DBPool.Exec(context.Background(), `
		INSERT INTO user_service_configs (user_id, config_yaml)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET
			config_yaml = EXCLUDED.config_yaml,
			updated_at = NOW();
	`, userID, req.ConfigYAML)
	if err != nil {
		c.Logger().Errorf("Failed to update user service config: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save configuration"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Configuration saved successfully"})
}
