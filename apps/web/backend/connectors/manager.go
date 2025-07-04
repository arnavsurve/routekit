package connectors

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

// Manager handles registration and routing for all connectors.
type Manager struct {
	connectors map[string]Connector
}

func NewManager() *Manager {
	return &Manager{
		connectors: make(map[string]Connector),
	}
}

func (m *Manager) Register(connector Connector) {
	m.connectors[connector.ServiceName()] = connector
}

func (m *Manager) RegisterRoutes(g *echo.Group) {
	g.POST("/:service", m.handleConnect)
	g.DELETE("/:service", m.handleDisconnect)
}

func (m *Manager) getConnector(serviceName string) (Connector, error) {
	connector, ok := m.connectors[serviceName]
	if !ok {
		return nil, fmt.Errorf("unknown service: %s", serviceName)
	}
	return connector, nil
}

func (m *Manager) handleConnect(c echo.Context) error {
	serviceName := c.Param("service")
	connector, err := m.getConnector(serviceName)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return connector.Connect(c)
}

func (m *Manager) handleDisconnect(c echo.Context) error {
	serviceName := c.Param("service")
	connector, err := m.getConnector(serviceName)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return connector.Disconnect(c)
}

func (m *Manager) HandleGetAllStatuses(c echo.Context) error {
	statuses := make(map[string]any)
	for name, connector := range m.connectors {
		status, err := connector.GetStatus(c)
		if err != nil {
			c.Logger().Errorf("Failed to get status for connector %s: %v", name, err)
			statuses[name] = map[string]any{"connected": false, "error": "failed to retrieve status"}
		} else {
			statuses[name] = status
		}

	}
	return c.JSON(http.StatusOK, statuses)
}
