package main

import (
	"log"
	"os"

	"github.com/arnavsurve/routekit/apps/web/backend/agent"
	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/apps/web/backend/connectors"
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

	appDB := &connectors.App{
		DBPool: db.GetPool(),
	}
	authHandler := &auth.Handler{
		DBPool:    db.GetPool(),
		JWTSecret: jwtSecret,
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

	// Authenticated routes
	api := e.Group("/api")
	api.Use(authHandler.AuthMiddleware)
	api.GET("/me", authHandler.HandleGetMe)

	// Connector routes
	connectorManager := connectors.NewManager()

	// GitHub connector
	connectorManager.Register(connectors.NewGitHubConnector(appDB))

	// Atlassian connector
	atlassianConnector := connectors.NewAtlassianConnector(appDB)
	connectorManager.Register(atlassianConnector)

	connectorRoutes := api.Group("/connectors")
	// For each connector, registerRoutes provides:
	// - POST connect
	// - DELETE disconnect
	connectorManager.RegisterRoutes(connectorRoutes)

	api.GET("/connectors/atlassian/connect", atlassianConnector.Connect)
	api.GET("/connectors/atlassian/callback", atlassianConnector.Callback)

	// Connectors status
	api.GET("/connectors/status", connectorManager.HandleGetAllStatuses)

	// WebSocket route
	e.GET("/ws", agent.HandleWebSocket, authHandler.AuthMiddleware)

	log.Println("Starting webapp server on http://localhost:3000")
	e.Logger.Fatal(e.Start(":3000"))
}
