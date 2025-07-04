package connectors

import (
	"context"
	"net/http"

	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type LinearConnector struct {
	app *App
}

func NewLinearConnector(app *App) *LinearConnector {
	return &LinearConnector{app: app}
}

func (l *LinearConnector) ServiceName() string {
	return "linear"
}

// Connect for Linear simply records that the user wants to use this service.
// The actual authentication is triggered on-demand by the gateway using mcp-remote.
func (l *LinearConnector) Connect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	_, err := l.app.DBPool.Exec(context.Background(), `
		INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, service_name) DO NOTHING;
	`, userID, l.ServiceName(), []byte{})
	if err != nil {
		c.Logger().Errorf("Failed to save Linear connection intent: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to enable Linear"})
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

// Disconnect removes the user's Linear connection record.
func (l *LinearConnector) Disconnect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	_, err := l.app.DBPool.Exec(context.Background(), `
		DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2
	`, userID, l.ServiceName())
	if err != nil {
		c.Logger().Errorf("Failed to disconnect Linear: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disconnect"})
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

// GetStatus checks if the user has a record of a Linear connection.
func (l *LinearConnector) GetStatus(c echo.Context) (map[string]any, error) {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var count int
	err := l.app.DBPool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM connected_services WHERE user_id = $1 AND service_name = $2",
		userID, l.ServiceName()).Scan(&count)
	if err != nil {
		return nil, err
	}

	return map[string]any{"connected": count > 0}, nil
}
