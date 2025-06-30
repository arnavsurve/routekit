package main

import (
	"log"
	"os"

	"github.com/arnavsurve/routekit/apps/web/backend/agent"
	"github.com/arnavsurve/routekit/apps/web/backend/auth"
	"github.com/arnavsurve/routekit/apps/web/backend/connectors"
	"github.com/arnavsurve/routekit/pkg/crypto"
	"github.com/arnavsurve/routekit/pkg/db"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type App struct {
	dbPool    *pgxpool.Pool
	jwtSecret []byte
}

const gatewayURL = "http://localhost:8080/mcp"

var upgrader = websocket.Upgrader{}

const jwtExpirationHours = 24

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
	connectorManager.Register(connectors.NewGitHubConnector(appDB))

	connectorRoutes := api.Group("/connectors")
	connectorManager.RegisterRoutes(connectorRoutes)

	// WebSocket route
	e.GET("/ws", agent.HandleWebSocket, authHandler.AuthMiddleware)

	log.Println("Starting webapp server on http://localhost:3000")
	e.Logger.Fatal(e.Start(":3000"))
}
