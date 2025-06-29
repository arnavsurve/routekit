package main

import (
	"context"
	"net/http"

	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type ConnectorRequest struct {
	Token string `json:"token"`
}

func (app *App) handleConnectGitHub(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*Claims)
	userID := claims.UserID

	var req ConnectorRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	encryptedToken, err := crypto.Encrypt([]byte(req.Token))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to secure token"})
	}

	_, err = app.dbPool.Exec(context.Background(), `
		INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, service_name) DO UPDATE SET
			credentials_encrypted = EXCLUDED.credentials_encrypted;
	`, userID, "github", encryptedToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save connection"})
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

func (app *App) handleDisconnectGitHub(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*Claims)
	userID := claims.UserID

	_, err := app.dbPool.Exec(context.Background(), `
		DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2
	`, userID, "github")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disconnect"})
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

func (app *App) handleGetConnectorStatus(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*Claims)
	userID := claims.UserID

	var count int
	err := app.dbPool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM connected_services WHERE user_id = $1 AND service_name = $2",
		userID, "github").Scan(&count)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "database error"})
	}

	return c.JSON(http.StatusOK, map[string]bool{"github_connected": count > 0})
}
