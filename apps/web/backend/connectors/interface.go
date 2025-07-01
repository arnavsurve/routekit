package connectors

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// Connector defines the standard interface for all service providers.
type Connector interface {
	// ServiceName returns the unique name of the service (e.g., "github").
	ServiceName() string
	// Connect handles the logic for connecting a user's account to the service.
	Connect(c echo.Context) error
	// Disconnect handles the logic for disconnecting a user's account.
	Disconnect(c echo.Context) error
	// GetStatus returns the connection status for the current user.
	GetStatus(c echo.Context) (map[string]any, error)
}

type App struct {
	DBPool *pgxpool.Pool
}
