package main

import (
	"log"
	"os"

	"github.com/arnavsurve/routekit/apps/web/backend/agent"
	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/apps/web/backend/llm"
	"github.com/arnavsurve/routekit/apps/web/backend/services"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/arnavsurve/routekit/pkg/db"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Failed to load environment variables: %v\n", err)
	}

	db.Init()
	defer db.Close()
	crypto.Init()

	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Fatalf("JWT_SECRET environment variable not set.")
	}

	anthropicAPIKey := os.Getenv("ANTHROPIC_API_KEY")
	if len(anthropicAPIKey) == 0 {
		log.Fatalf("ANTHROPIC_API_KEY environment variable not set.")
	}

	authHandler := &auth.Handler{
		DBPool:    db.GetPool(),
		JWTSecret: jwtSecret,
	}
	servicesHandler := &services.ServicesHandler{
		DBPool: db.GetPool(),
	}
	llmHandler := &llm.LLMHandler{
		DBPool: db.GetPool(),
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("anthropic_api_key", anthropicAPIKey)
			return next(c)
		}
	})

	e.Static("/", "public")
	e.POST("/api/signup", authHandler.HandleSignup)
	e.POST("/api/login", authHandler.HandleLogin)

	api := e.Group("/api")
	api.Use(authHandler.AuthMiddleware)
	api.GET("/me", authHandler.HandleGetMe)

	// User service configuration routes
	api.GET("/user/services", servicesHandler.HandleGetUserServices)
	api.POST("/user/services", servicesHandler.HandleCreateUserService)
	api.DELETE("/user/services/:id", servicesHandler.HandleDeleteUserService)

	// User LLM configuration routes
	api.GET("/user/llm-config", llmHandler.HandleGetLLMConfig)
	api.POST("/user/llm-config", llmHandler.HandleSetLLMConfig)
	api.DELETE("/user/llm-config/:id", llmHandler.HandleDeleteLLMConfig)
	api.PUT("/user/llm-config/:id/default", llmHandler.HandleSetDefaultLLMConfig)
	api.POST("/user/llm-config/test", llmHandler.HandleTestLLMConfig)

	// Generic Connector routes
	api.POST("/connectors/:service/token", servicesHandler.HandleTokenConnect) // For PAT/API Key
	api.GET("/connectors/:service/oauth", servicesHandler.HandleOAuthConnect)  // For OAuth redirects
	api.DELETE("/connectors/:service", servicesHandler.HandleDisconnect)
	api.GET("/connectors/status", servicesHandler.HandleGetAllStatuses)

	// Generic OAuth callback
	api.GET("/connectors/callback", servicesHandler.HandleCallback)

	// WebSocket route for the agent
	e.GET("/ws", agent.HandleWebSocket, authHandler.AuthMiddleware)

	log.Println("Starting webapp server on http://localhost:3000")
	e.Logger.Fatal(e.Start(":3000"))
}

