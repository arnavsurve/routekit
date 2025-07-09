package llm

import (
	"context"
	"net/http"
	"time"

	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/arnavsurve/routekit/pkg/llm"
	"github.com/arnavsurve/routekit/pkg/llm/providers"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

type LLMHandler struct {
	DBPool *pgxpool.Pool
}

// LLMConfigRequest represents the request payload for setting LLM configuration
type LLMConfigRequest struct {
	ProviderType string `json:"provider_type" validate:"required,oneof=anthropic openai"`
	APIKey       string `json:"api_key" validate:"required"`
	BaseURL      string `json:"base_url,omitempty"`
	Model        string `json:"model,omitempty"`
	IsDefault    bool   `json:"is_default"`
}

// LLMConfigResponse represents an LLM configuration for API responses
type LLMConfigResponse struct {
	ID           string    `json:"id"`
	ProviderType string    `json:"provider_type"`
	BaseURL      string    `json:"base_url,omitempty"`
	Model        string    `json:"model,omitempty"`
	IsDefault    bool      `json:"is_default"`
	CreatedAt    time.Time `json:"created_at"`
}

// LLMTestRequest represents the request for testing an LLM configuration
type LLMTestRequest struct {
	ProviderType string `json:"provider_type" validate:"required,oneof=anthropic openai"`
	APIKey       string `json:"api_key" validate:"required"`
	BaseURL      string `json:"base_url,omitempty"`
	Model        string `json:"model,omitempty"`
}

// HandleGetLLMConfig returns the LLM configurations for a user
func (h *LLMHandler) HandleGetLLMConfig(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	rows, err := h.DBPool.Query(c.Request().Context(), `
		SELECT id, provider_type, base_url, model, is_default, created_at
		FROM user_llm_configs 
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch LLM configurations",
		})
	}
	defer rows.Close()

	var configs []LLMConfigResponse
	for rows.Next() {
		var config LLMConfigResponse
		var baseURL, model *string
		err := rows.Scan(&config.ID, &config.ProviderType, &baseURL, &model, &config.IsDefault, &config.CreatedAt)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to scan configuration: " + err.Error(),
			})
		}

		if baseURL != nil {
			config.BaseURL = *baseURL
		}
		if model != nil {
			config.Model = *model
		}

		configs = append(configs, config)
	}

	return c.JSON(http.StatusOK, map[string]any{
		"configs": configs,
	})
}

// HandleSetLLMConfig creates/modifies an LLM configuration for a user
func (h *LLMHandler) HandleSetLLMConfig(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	var req LLMConfigRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Validate the provider configuration
	config := llm.ProviderConfig{
		Type:    req.ProviderType,
		APIKey:  req.APIKey,
		BaseURL: req.BaseURL,
		Model:   req.Model,
	}

	provider, err := providers.NewProvider(config)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid provider configuration",
		})
	}

	if err := provider.ValidateConfig(config); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	// Encrypt the API key
	encryptedAPIKey, err := crypto.Encrypt([]byte(req.APIKey))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to encrypt API key",
		})
	}

	// Start transaction
	tx, err := h.DBPool.Begin(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to start transaction",
		})
	}
	defer tx.Rollback(c.Request().Context())

	// If setting as default, unset other defaults first
	if req.IsDefault {
		_, err = tx.Exec(c.Request().Context(), `
			UPDATE user_llm_configs 
			SET is_default = false 
			WHERE user_id = $1
		`, userID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to update existing configurations: " + err.Error(),
			})
		}
	}

	// Insert or update the configuration
	var configID string

	// Handle NULL values for optional fields
	var baseURL, model any
	if req.BaseURL == "" {
		baseURL = nil
	} else {
		baseURL = req.BaseURL
	}
	if req.Model == "" {
		model = nil
	} else {
		model = req.Model
	}

	err = tx.QueryRow(c.Request().Context(), `
		INSERT INTO user_llm_configs (user_id, provider_type, api_key_encrypted, base_url, model, is_default)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, provider_type) 
		DO UPDATE SET 
			api_key_encrypted = EXCLUDED.api_key_encrypted,
			base_url = EXCLUDED.base_url,
			model = EXCLUDED.model,
			is_default = EXCLUDED.is_default
		RETURNING id
	`, userID, req.ProviderType, encryptedAPIKey, baseURL, model, req.IsDefault).Scan(&configID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to save configuration: " + err.Error(),
		})
	}

	// Commit transaction
	if err = tx.Commit(c.Request().Context()); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to commit transaction",
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"success":   true,
		"config_id": configID,
	})
}

// HandleDeleteLLMConfig deletes an LLM configuration for a user
func (h *LLMHandler) HandleDeleteLLMConfig(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	configID := c.Param("id")
	if configID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Configuration ID is required",
		})
	}

	result, err := h.DBPool.Exec(c.Request().Context(), `
		DELETE FROM user_llm_configs 
		WHERE id = $1 AND user_id = $2
	`, configID, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete configuration",
		})
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Configuration not found",
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"success": true,
	})
}

// HandleSetDefaultLLMConfig sets a configuration as the default without requiring API key
func (h *LLMHandler) HandleSetDefaultLLMConfig(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*auth.Claims)
	userID := claims.UserID

	configID := c.Param("id")
	if configID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Configuration ID is required",
		})
	}

	// Start transaction
	tx, err := h.DBPool.Begin(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to start transaction",
		})
	}
	defer tx.Rollback(c.Request().Context())

	// First, unset all defaults for this user
	_, err = tx.Exec(c.Request().Context(), `
		UPDATE user_llm_configs 
		SET is_default = false 
		WHERE user_id = $1
	`, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to unset existing defaults: " + err.Error(),
		})
	}

	// Then set the specified config as default
	result, err := tx.Exec(c.Request().Context(), `
		UPDATE user_llm_configs 
		SET is_default = true 
		WHERE id = $1 AND user_id = $2
	`, configID, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to set default configuration: " + err.Error(),
		})
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Configuration not found",
		})
	}

	// Commit transaction
	if err = tx.Commit(c.Request().Context()); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to commit transaction: " + err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"success": true,
	})
}

// HandleTestLLMConfig validates an LLM configuration for a user
func (h *LLMHandler) HandleTestLLMConfig(c echo.Context) error {
	var req LLMTestRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request format",
		})
	}

	// Create provider configuration
	config := llm.ProviderConfig{
		Type:    req.ProviderType,
		APIKey:  req.APIKey,
		BaseURL: req.BaseURL,
		Model:   req.Model,
	}

	// Test the configuration by creating a provider
	provider, err := providers.NewProvider(config)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "Invalid provider configuration: " + err.Error(),
		})
	}

	// Validate configuration
	if err := provider.ValidateConfig(config); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "Configuration validation failed: " + err.Error(),
		})
	}

	testMessage := llm.MessageRequest{
		Messages: []llm.Message{
			{Role: "user", Content: "Hello, this is a test message. Please respond briefly."},
		},
		MaxTokens: 100,
		Model:     req.Model,
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), 45*time.Second)
	defer cancel()

	response, err := provider.SendMessage(ctx, testMessage)
	if err != nil {
		errorMsg := err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			errorMsg = "Request timeout - API took too long to respond. Please check your API key and network connection."
		}
		return c.JSON(http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   errorMsg,
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"success":          true,
		"test_response":    response.Content,
		"usage":            response.Usage,
		"supported_models": provider.GetSupportedModels(),
	})
}
