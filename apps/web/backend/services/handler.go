package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/pkg/config"
	"github.com/arnavsurve/routekit/pkg/crypto"
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

type TokenConnectRequest struct {
	Token string `json:"token"`
}

// getUserServiceConfig is a helper to fetch and find a specific service config for a user
func (h *ServicesHandler) getUserServiceConfig(userID, serviceName string) (*config.ServiceConfig, error) {
	var configYAML string
	err := h.DBPool.QueryRow(context.Background(), "SELECT config_yaml FROM user_service_configs WHERE user_id = $1", userID).Scan(&configYAML)
	if err != nil {
		return nil, fmt.Errorf("user configuration not found")
	}

	var serviceFile struct {
		Services []config.ServiceConfig `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(configYAML), &serviceFile); err != nil {
		return nil, fmt.Errorf("invalid service configuration yaml")
	}

	for i := range serviceFile.Services {
		if serviceFile.Services[i].Name == serviceName {
			return &serviceFile.Services[i], nil
		}
	}
	return nil, fmt.Errorf("service not found in your configuration")
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

// HandleTokenConnect handles connections for services using PATs or API keys.
func (h *ServicesHandler) HandleTokenConnect(c echo.Context) error {
	serviceName := c.Param("service")
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var req TokenConnectRequest
	if err := c.Bind(&req); err != nil || req.Token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}

	encryptedToken, err := crypto.Encrypt([]byte(req.Token))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to secure token"})
	}

	_, err = h.DBPool.Exec(context.Background(),
		`INSERT INTO connected_services (user_id, service_name, credentials_encrypted) VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, service_name) DO UPDATE SET credentials_encrypted = EXCLUDED.credentials_encrypted`,
		userID, serviceName, encryptedToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save connection"})
	}
	return c.JSON(http.StatusOK, map[string]bool{"success": true})
}

// HandleOAuthConnect is the generic entry point for browser-based OAuth flows.
func (h *ServicesHandler) HandleOAuthConnect(c echo.Context) error {
	serviceName := c.Param("service")
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	serviceConfig, err := h.getUserServiceConfig(userID, serviceName)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	if serviceConfig.Auth.Type != "oauth2.1" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "service is not configured for oauth2.1"})
	}
	
	state, err := generateRandomString(16)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not generate state"})
	}

	// Store state to validate the callback
	_, err = h.DBPool.Exec(context.Background(),
		"INSERT INTO oauth_sessions (state, user_id, service_name, code_verifier) VALUES ($1, $2, $3, $4)",
		state, userID, serviceName, "") // code_verifier not needed here
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to initiate auth session"})
	}

	redirectURI := fmt.Sprintf("http://%s/api/connectors/callback", c.Request().Host)
	authURLParams := url.Values{
		"client_id":     {os.Getenv(serviceConfig.Auth.ClientIDEnv)},
		"scope":         {strings.Join(serviceConfig.Auth.Scopes, " ")},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"response_type": {"code"},
		"prompt":        {"consent"},
	}
	if serviceConfig.Auth.Audience != "" {
		authURLParams.Set("audience", serviceConfig.Auth.Audience)
	}

	authURL := serviceConfig.Auth.AuthorizationURL + "?" + authURLParams.Encode()
	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// HandleCallback is the generic OAuth callback handler.
func (h *ServicesHandler) HandleCallback(c echo.Context) error {
	code := c.QueryParam("code")
	state := c.QueryParam("state")
	if code == "" || state == "" {
		return c.String(http.StatusBadRequest, "Authorization code or state is missing.")
	}

	var userID, serviceName string
	err := h.DBPool.QueryRow(context.Background(), "SELECT user_id, service_name FROM oauth_sessions WHERE state = $1", state).Scan(&userID, &serviceName)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid or expired state. Please try the authentication flow again.")
	}
	defer h.DBPool.Exec(context.Background(), "DELETE FROM oauth_sessions WHERE state = $1", state)

	tokenData, err := h.exchangeCodeForToken(c, userID, serviceName, code)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to exchange code for token: "+err.Error())
	}

	encryptedTokens, err := crypto.Encrypt(tokenData)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to secure tokens.")
	}

	_, err = h.DBPool.Exec(context.Background(), `
		INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, service_name) DO UPDATE SET
			credentials_encrypted = EXCLUDED.credentials_encrypted;
	`, userID, serviceName, encryptedTokens)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to save connection.")
	}

	return c.Redirect(http.StatusFound, "/settings.html?status=success&service="+serviceName)
}

// exchangeCodeForToken handles the token exchange for a given provider.
func (h *ServicesHandler) exchangeCodeForToken(c echo.Context, userID, serviceName, code string) ([]byte, error) {
	serviceConfig, err := h.getUserServiceConfig(userID, serviceName)
	if err != nil {
		return nil, err
	}

	redirectURI := fmt.Sprintf("http://%s/api/connectors/callback", c.Request().Host)
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {os.Getenv(serviceConfig.Auth.ClientIDEnv)},
		"client_secret": {os.Getenv(serviceConfig.Auth.ClientSecretEnv)},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	resp, err := http.PostForm(serviceConfig.Auth.TokenURL, data)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil { return nil, err }

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed for %s: status %d, body %s", serviceName, resp.StatusCode, string(body))
	}

	return body, nil
}

// HandleDisconnect is a generic endpoint to remove a service connection.
func (h *ServicesHandler) HandleDisconnect(c echo.Context) error {
	serviceName := c.Param("service")
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	_, err := h.DBPool.Exec(context.Background(), `
		DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2
	`, userID, serviceName)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disconnect"})
	}
	return c.JSON(http.StatusOK, map[string]bool{"success": true})
}

// HandleGetAllStatuses is generic and remains useful.
func (h *ServicesHandler) HandleGetAllStatuses(c echo.Context) error {
    user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

    rows, err := h.DBPool.Query(context.Background(), "SELECT service_name FROM connected_services WHERE user_id = $1", userID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"error": "db error"})
    }
    defer rows.Close()

    statuses := make(map[string]any)
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
             return c.JSON(http.StatusInternalServerError, map[string]string{"error": "db scan error"})
        }
        statuses[name] = map[string]any{"connected": true}
    }
    return c.JSON(http.StatusOK, statuses)
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}