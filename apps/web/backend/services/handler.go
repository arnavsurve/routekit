package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/pkg/config"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

type ServicesHandler struct {
	DBPool *pgxpool.Pool
}

// HandleGetUserServices returns all service configurations for the user
func (h *ServicesHandler) HandleGetUserServices(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	rows, err := h.DBPool.Query(context.Background(), `
		SELECT id, service_name, transport_type, mcp_server_url, auth_type, 
		       auth_config_encrypted, scopes, audience
		FROM user_service_configs 
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to load services"})
	}
	defer rows.Close()

	var services []config.ServiceConfig
	for rows.Next() {
		var service config.ServiceConfig
		var authConfigEncrypted []byte
		var scopesJSON []byte

		err := rows.Scan(
			&service.ID, &service.Name, &service.TransportType, &service.MCPServerURL,
			&service.AuthType, &authConfigEncrypted, &scopesJSON, &service.Audience,
		)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Failed to scan service: %v", err)})
		}

		// Parse scopes JSON
		var scopes []string
		if scopesJSON != nil {
			if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
				scopes = []string{}
			}
		} else {
			scopes = []string{}
		}

		// Decrypt auth config
		authConfigJSON, err := crypto.Decrypt(authConfigEncrypted)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to decrypt auth config"})
		}

		if err := json.Unmarshal(authConfigJSON, &service.AuthConfig); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to parse auth config"})
		}

		service.UserID = userID
		service.Scopes = scopes
		services = append(services, service)
	}

	return c.JSON(http.StatusOK, services)
}

// HandleCreateUserService creates a new service configuration
func (h *ServicesHandler) HandleCreateUserService(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var req struct {
		ServiceName      string   `json:"service_name"`
		TransportType    string   `json:"transport_type"`
		MCPServerURL     string   `json:"mcp_server_url"`
		AuthType         string   `json:"auth_type"`
		ClientID         string   `json:"client_id,omitempty"`
		ClientSecret     string   `json:"client_secret,omitempty"`
		AuthorizationURL string   `json:"authorization_url,omitempty"`
		TokenURL         string   `json:"token_url,omitempty"`
		Scopes           []string `json:"scopes,omitempty"`
		Audience         string   `json:"audience,omitempty"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	// Create service config  
	service := config.ServiceConfig{
		UserID:        userID,
		Name:          req.ServiceName,
		TransportType: req.TransportType,
		MCPServerURL:  req.MCPServerURL,
		AuthType:      req.AuthType,
		Scopes:        req.Scopes,
		Audience:      req.Audience,
	}
	
	// Initialize empty slices if nil
	if service.Scopes == nil {
		service.Scopes = []string{}
	}

	// Create appropriate auth config based on auth type
	if service.AuthType == "mcp_remote_managed" {
		service.AuthConfig = config.AuthConfig{
			Type: "mcp_remote_managed",
		}
	} else {
		service.AuthConfig = config.AuthConfig{
			Type:             req.AuthType,
			ClientID:         req.ClientID,
			ClientSecret:     req.ClientSecret,
			AuthorizationURL: req.AuthorizationURL,
			TokenURL:         req.TokenURL,
		}
	}

	// Validate
	if err := config.ValidateServiceConfig(&service); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Check for duplicate MCP server URL for this user
	var exists bool
	err := h.DBPool.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM user_service_configs WHERE user_id = $1 AND mcp_server_url = $2)",
		userID, req.MCPServerURL).Scan(&exists)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to check for duplicates"})
	}
	if exists {
		return c.JSON(http.StatusConflict, map[string]string{"error": "Service with this MCP server URL already exists"})
	}

	// Encrypt auth config
	authConfigJSON, err := json.Marshal(service.AuthConfig)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to serialize auth config"})
	}

	authConfigEncrypted, err := crypto.Encrypt(authConfigJSON)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to encrypt auth config"})
	}

	// Serialize scopes as JSON
	scopesJSON, err := json.Marshal(service.Scopes)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to serialize scopes"})
	}

	// Insert into database
	var serviceID string
	err = h.DBPool.QueryRow(context.Background(), `
		INSERT INTO user_service_configs 
		(user_id, service_name, transport_type, mcp_server_url, auth_type, auth_config_encrypted, scopes, audience)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, userID, req.ServiceName, req.TransportType, req.MCPServerURL, req.AuthType,
		authConfigEncrypted, scopesJSON, service.Audience).Scan(&serviceID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Failed to create service: %v", err)})
	}

	service.ID = serviceID
	return c.JSON(http.StatusCreated, service)
}

// HandleDeleteUserService deletes a service configuration
func (h *ServicesHandler) HandleDeleteUserService(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID
	serviceID := c.Param("id")

	// Delete service config
	result, err := h.DBPool.Exec(context.Background(),
		"DELETE FROM user_service_configs WHERE id = $1 AND user_id = $2",
		serviceID, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete service"})
	}

	if result.RowsAffected() == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Service not found"})
	}

	// Also disconnect the service if it's connected
	_, _ = h.DBPool.Exec(context.Background(),
		"DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2",
		userID, serviceID) // Using serviceID as service name for now

	return c.JSON(http.StatusOK, map[string]bool{"success": true})
}

// Helper function to get user service config by service name
func (h *ServicesHandler) getUserServiceConfig(userID, serviceName string) (*config.ServiceConfig, error) {
	var service config.ServiceConfig
	var authConfigEncrypted []byte
	var scopesJSON []byte

	err := h.DBPool.QueryRow(context.Background(), `
		SELECT id, service_name, transport_type, mcp_server_url, auth_type, 
		       auth_config_encrypted, scopes, audience
		FROM user_service_configs 
		WHERE user_id = $1 AND service_name = $2
	`, userID, serviceName).Scan(
		&service.ID, &service.Name, &service.TransportType, &service.MCPServerURL,
		&service.AuthType, &authConfigEncrypted, &scopesJSON, &service.Audience,
	)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}

	// Parse scopes JSON
	var scopes []string
	if scopesJSON != nil {
		if err := json.Unmarshal(scopesJSON, &scopes); err != nil {
			scopes = []string{}
		}
	} else {
		scopes = []string{}
	}

	// Decrypt auth config
	authConfigJSON, err := crypto.Decrypt(authConfigEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth config: %w", err)
	}

	if err := json.Unmarshal(authConfigJSON, &service.AuthConfig); err != nil {
		return nil, fmt.Errorf("failed to parse auth config: %w", err)
	}

	service.UserID = userID
	service.Scopes = scopes
	return &service, nil
}

// HandleOAuthConnect initiates OAuth flow for a service
func (h *ServicesHandler) HandleOAuthConnect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID
	serviceName := c.Param("service")

	serviceConfig, err := h.getUserServiceConfig(userID, serviceName)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	if serviceConfig.AuthType == "mcp_remote_managed" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "SSE services with mcp_remote_managed auth are handled automatically by the gateway. No manual connection needed.",
		})
	}

	if serviceConfig.AuthType != "oauth2.1" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "service is not configured for oauth2.1"})
	}

	state, err := generateRandomString(16)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not generate state"})
	}

	// Store state to validate the callback
	_, err = h.DBPool.Exec(context.Background(),
		"INSERT INTO oauth_sessions (state, user_id, service_name, code_verifier) VALUES ($1, $2, $3, $4)",
		state, userID, serviceName, "")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to initiate auth session"})
	}

	redirectURI := fmt.Sprintf("http://%s/api/connectors/callback", c.Request().Host)
	authURLParams := url.Values{
		"client_id":     {serviceConfig.AuthConfig.ClientID},
		"scope":         {strings.Join(serviceConfig.Scopes, " ")},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"response_type": {"code"},
		"prompt":        {"consent"},
	}
	if serviceConfig.Audience != "" {
		authURLParams.Set("audience", serviceConfig.Audience)
	}

	authURL := serviceConfig.AuthConfig.AuthorizationURL + "?" + authURLParams.Encode()
	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// HandleTokenConnect handles PAT/token-based authentication
func (h *ServicesHandler) HandleTokenConnect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID
	serviceName := c.Param("service")

	var req struct {
		Token string `json:"token"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	serviceConfig, err := h.getUserServiceConfig(userID, serviceName)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	if serviceConfig.AuthType != "pat" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "service is not configured for token auth"})
	}

	// Encrypt and store the token
	credentials := map[string]any{
		"token": req.Token,
	}
	credentialsJSON, _ := json.Marshal(credentials)
	credentialsEncrypted, err := crypto.Encrypt(credentialsJSON)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to encrypt credentials"})
	}

	_, err = h.DBPool.Exec(context.Background(), `
		INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, service_name) 
		DO UPDATE SET credentials_encrypted = EXCLUDED.credentials_encrypted
	`, userID, serviceName, credentialsEncrypted)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to store credentials"})
	}

	return c.JSON(http.StatusOK, map[string]bool{"success": true})
}

// HandleCallback handles OAuth callback
func (h *ServicesHandler) HandleCallback(c echo.Context) error {
	code := c.QueryParam("code")
	state := c.QueryParam("state")

	if code == "" || state == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Missing code or state parameter"})
	}

	// Get session info
	var userID, serviceName string
	err := h.DBPool.QueryRow(context.Background(),
		"SELECT user_id, service_name FROM oauth_sessions WHERE state = $1", state).Scan(&userID, &serviceName)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid or expired state"})
	}

	// Delete the session
	_, _ = h.DBPool.Exec(context.Background(), "DELETE FROM oauth_sessions WHERE state = $1", state)

	serviceConfig, err := h.getUserServiceConfig(userID, serviceName)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	// Exchange code for token
	tokenData, err := h.exchangeCodeForToken(c, serviceConfig, code)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Store encrypted credentials
	credentialsEncrypted, err := crypto.Encrypt(tokenData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to encrypt credentials"})
	}

	_, err = h.DBPool.Exec(context.Background(), `
		INSERT INTO connected_services (user_id, service_name, credentials_encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, service_name) 
		DO UPDATE SET credentials_encrypted = EXCLUDED.credentials_encrypted
	`, userID, serviceName, credentialsEncrypted)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to store credentials"})
	}

	return c.HTML(http.StatusOK, `
		<script>
			window.opener.postMessage({type: 'oauth_success'}, '*');
			window.close();
		</script>
		<p>Authentication successful! You can close this window.</p>
	`)
}

func (h *ServicesHandler) exchangeCodeForToken(c echo.Context, serviceConfig *config.ServiceConfig, code string) ([]byte, error) {
	redirectURI := fmt.Sprintf("http://%s/api/connectors/callback", c.Request().Host)
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {serviceConfig.AuthConfig.ClientID},
		"client_secret": {serviceConfig.AuthConfig.ClientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	resp, err := http.PostForm(serviceConfig.AuthConfig.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: status %d", resp.StatusCode)
	}

	var tokenResponse map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, err
	}

	return json.Marshal(tokenResponse)
}

// HandleDisconnect disconnects a service
func (h *ServicesHandler) HandleDisconnect(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID
	serviceName := c.Param("service")

	_, err := h.DBPool.Exec(context.Background(),
		"DELETE FROM connected_services WHERE user_id = $1 AND service_name = $2",
		userID, serviceName)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disconnect"})
	}
	return c.JSON(http.StatusOK, map[string]bool{"success": true})
}

// HandleGetAllStatuses returns connection status for all services
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

