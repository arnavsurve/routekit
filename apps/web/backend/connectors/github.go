package connectors

import (
	"context"
	"net/http"

	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type GitHubConnector struct {
	app *App
}

func NewGitHubConnector(app *App) *GitHubConnector {
	return &GitHubConnector{app: app}
}

type connectRequest struct {
	Token string `json:"token"`
}

func (g *GitHubConnector) ServiceName() string {
	return "github"
}

func (g *GitHubConnector) Connect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var req connectRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	encryptedToken, err := crypto.Encrypt([]byte(req.Token))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to secure token"})
	}

	_, err = g.app.DBPool.Exec(context.Background(), `
		INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, service_name) DO UPDATE SET
			credentials_encrypted = EXCLUDED.credentials_encrypted;
	`, userID, g.ServiceName(), encryptedToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save connection"})
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

func (g *GitHubConnector) Disconnect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	_, err := g.app.DBPool.Exec(context.Background(), `
		DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2
	`, userID, "github")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disconnect"})
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

func (g *GitHubConnector) GetStatus(c echo.Context) (map[string]any, error) {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var count int
	err := g.app.DBPool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM connected_services WHERE user_id = $1 AND service_name = $2",
		userID, g.ServiceName()).Scan(&count)
	if err != nil {
		return nil, err
	}

	return map[string]any{"connected": count > 0}, nil
}
