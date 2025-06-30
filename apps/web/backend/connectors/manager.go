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
	g.GET("/status", m.handleGetAllStatuses)
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

func (m *Manager) handleGetAllStatuses(c echo.Context) error {
	statuses := make(map[string]any)
	for name, connector := range m.connectors {
		statuses[name] = connector.GetStatus(c)
	}
	return c.JSON(http.StatusOK, statuses)
}
