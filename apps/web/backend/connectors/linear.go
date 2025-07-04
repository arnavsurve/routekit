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

// Connect for Linear is a placeholder. The actual connection is triggered
// on-demand by the gateway when a tool is first used. This endpoint
// is here for UI consistency but won't be called directly in the auth flow.
func (l *LinearConnector) Connect(c echo.Context) error {
	// The real auth flow is initiated by the gateway.
	// This endpoint can simply confirm that the service is configured.
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Linear connection is managed by the Routekit Gateway. Please use the chat interface to trigger authentication.",
	})
}

// Disconnect removes the user's Linear credentials.
// For mcp-remote, this means deleting the auth files.
func (l *LinearConnector) Disconnect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	// For mcp-remote, "disconnecting" means clearing the cached credentials
	// on the gateway's file system. We can't do that directly from here,
	// but we can remove our record of the connection.
	_, err := l.app.DBPool.Exec(context.Background(), `
		DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2
	`, userID, l.ServiceName())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disconnect"})
	}

	// NOTE: This does not clear the `~/.mcp-auth` directory used by mcp-remote.
	// A more robust solution would involve an internal API on the gateway to
	// trigger a cleanup of the auth directory for a specific user/service.
	// For now, this is sufficient to remove it from the user's list of connected services.

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
	// Note: We are just checking if we have a record. A more robust check
	// would involve pinging the gateway's cached client.
	err := l.app.DBPool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM connected_services WHERE user_id = $1 AND service_name = $2",
		userID, l.ServiceName()).Scan(&count)
	if err != nil {
		return nil, err
	}

	return map[string]any{"connected": count > 0}, nil
}