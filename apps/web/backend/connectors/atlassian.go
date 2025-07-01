package connectors

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type AtlassianConnector struct {
	app *App
}

func NewAtlassianConnector(app *App) *AtlassianConnector {
	return &AtlassianConnector{app: app}
}

func (a *AtlassianConnector) ServiceName() string {
	return "atlassian"
}

// Connect redirects the user to the Atlassian consent screen.
func (a *AtlassianConnector) Connect(c echo.Context) error {
	scopes := []string{
		"read:jira-work",
		"write:jira-work",
		"read:confluence-content.all",
		"write:confluence-content",
		"read:jira-user",
		"offline_access",
	}

	redirectURI := fmt.Sprintf("http://%s/api/connectors/atlassian/callback", c.Request().Host)

	authURL := "https://auth.atlassian.com/authorize?" + url.Values{
		"audience":      {"api.atlassian.com"},
		"client_id":     {os.Getenv("ATLASSIAN_CLIENT_ID")},
		"scope":         {strings.Join(scopes, " ")},
		"redirect_uri":  {redirectURI},
		"state":         {"a-secure-random-state-string"}, // TODO: Implement proper state handling for CSRF protection
		"response_type": {"code"},
		"prompt":        {"consent"},
	}.Encode()

	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback handles the redirect from Atlassian, exchanges the code for tokens,
// and stores them in the database.
func (a *AtlassianConnector) Callback(c echo.Context) error {
	code := c.QueryParam("code")
	if code == "" {
		return c.String(http.StatusBadRequest, "Authorization code is missing.")
	}

	tokenData, err := a.exchangeCodeForToken(c.Request().Context(), code, c.Request().Host)
	if err != nil {
		c.Logger().Errorf("Atlassian token exchange failed: %v", err)
		return c.String(http.StatusInternalServerError, "Failed to get token from Atlassian.")
	}

	encryptedTokens, err := crypto.Encrypt(tokenData)
	if err != nil {
		c.Logger().Errorf("Failed to encrypt Atlassian tokens: %v", err)
		return c.String(http.StatusInternalServerError, "Failed to secure tokens.")
	}

	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	_, err = a.app.DBPool.Exec(context.Background(), `
		INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, service_name) DO UPDATE SET
			credentials_encrypted = EXCLUDED.credentials_encrypted;
	`, userID, a.ServiceName(), encryptedTokens)
	if err != nil {
		c.Logger().Errorf("Failed to save Atlassian connection: %v", err)
		return c.String(http.StatusInternalServerError, "Failed to save connection.")
	}

	return c.Redirect(http.StatusFound, "/settings.html")
}

func (a *AtlassianConnector) exchangeCodeForToken(ctx context.Context, code, requestHost string) ([]byte, error) {
	redirectURI := fmt.Sprintf("http://%s/api/connectors/atlassian./callback", requestHost)

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {os.Getenv("ATLASSIAN_CLIENT_ID")},
		"client_secret": {os.Getenv("ATLASSIAN_CLIENT_SECRET")},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://auth.atlassian.com/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange (Atlassian) failed: status %d, body %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// Disconnect removes the user's Atlassian connection from the database.
func (a *AtlassianConnector) Disconnect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	_, err := a.app.DBPool.Exec(context.Background(), `
		DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2
	`, userID, a.ServiceName())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disconnect"})
	}

	return c.JSON(http.StatusOK, map[string]bool{
		"success": true,
	})
}

func (a *AtlassianConnector) GetStatus(c echo.Context) (map[string]any, error) {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var count int
	err := a.app.DBPool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM connected_services WHERE user_id = $1 AND service_name = $2",
		userID, a.ServiceName()).Scan(&count)
	if err != nil {
		return nil, err
	}

	return map[string]any{"connected": count > 0}, nil
}
