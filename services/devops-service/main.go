package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("DevOps & CI Server Service", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	)

	// Add DevOps tools
	s.AddTool(
		mcp.NewTool("get_pipeline_status",
			mcp.WithDescription("Get status of a CI/CD pipeline"),
			mcp.WithString("pipeline_id", mcp.Required(), mcp.Description("ID of the pipeline to check")),
		),
		handleGetPipelineStatus,
	)

	s.AddTool(
		mcp.NewTool("trigger_deployment",
			mcp.WithDescription("Trigger deployment to an environment"),
			mcp.WithString("env", mcp.Required(), mcp.Description("Target environment (dev, staging, prod)")),
			mcp.WithString("service", mcp.Required(), mcp.Description("Service name to deploy")),
			mcp.WithString("version", mcp.Description("Version to deploy (defaults to latest)")),
		),
		handleTriggerDeployment,
	)

	s.AddTool(
		mcp.NewTool("rollback_deployment",
			mcp.WithDescription("Rollback deployment to a previous version"),
			mcp.WithString("env", mcp.Required(), mcp.Description("Target environment (dev, staging, prod)")),
			mcp.WithString("version", mcp.Required(), mcp.Description("Version to rollback to")),
			mcp.WithString("service", mcp.Description("Service name (optional, defaults to all services)")),
		),
		handleRollbackDeployment,
	)

	s.AddTool(
		mcp.NewTool("get_error_logs",
			mcp.WithDescription("Get error logs for a service"),
			mcp.WithString("service", mcp.Required(), mcp.Description("Service name to get logs for")),
			mcp.WithString("since", mcp.Required(), mcp.Description("Time period (e.g., '1h', '24h', '7d')")),
			mcp.WithString("env", mcp.Description("Environment filter (optional)")),
		),
		handleGetErrorLogs,
	)

	s.AddTool(
		mcp.NewTool("list_deployments",
			mcp.WithDescription("List recent deployments"),
			mcp.WithString("env", mcp.Description("Environment filter (optional)")),
			mcp.WithString("service", mcp.Description("Service filter (optional)")),
			mcp.WithString("limit", mcp.Description("Number of results to return (default 10)")),
		),
		handleListDeployments,
	)

	s.AddTool(
		mcp.NewTool("get_service_health",
			mcp.WithDescription("Get health status of services"),
			mcp.WithString("env", mcp.Required(), mcp.Description("Environment to check (dev, staging, prod)")),
			mcp.WithString("service", mcp.Description("Specific service to check (optional)")),
		),
		handleGetServiceHealth,
	)

	s.AddTool(
		mcp.NewTool("trigger_incident_report",
			mcp.WithDescription("Create an incident report for a service outage or issue"),
			mcp.WithString("title", mcp.Required(), mcp.Description("Incident title")),
			mcp.WithString("description", mcp.Required(), mcp.Description("Incident description")),
			mcp.WithString("severity", mcp.Required(), mcp.Description("Incident severity (low, medium, high, critical)")),
			mcp.WithString("affected_service", mcp.Required(), mcp.Description("Primary affected service")),
			mcp.WithString("environment", mcp.Description("Affected environment (defaults to prod)")),
		),
		handleTriggerIncidentReport,
	)

	s.AddTool(
		mcp.NewTool("get_service_status",
			mcp.WithDescription("Get detailed status of a specific service including recent errors"),
			mcp.WithString("service", mcp.Required(), mcp.Description("Service name to check")),
			mcp.WithString("env", mcp.Description("Environment (defaults to prod)")),
		),
		handleGetServiceStatus,
	)

	// Add resources
	s.AddResource(
		mcp.NewResource(
			"pipeline://{pipeline_id}",
			"Pipeline Details",
			mcp.WithResourceDescription("Detailed pipeline information and build history"),
			mcp.WithMIMEType("application/json"),
		),
		handlePipelineResource,
	)

	s.AddResource(
		mcp.NewResource(
			"deployment://{deployment_id}",
			"Deployment Details",
			mcp.WithResourceDescription("Detailed deployment information and status"),
			mcp.WithMIMEType("application/json"),
		),
		handleDeploymentResource,
	)

	// Print capabilities
	fmt.Println("=== DevOps & CI Server Service Capabilities ===")
	fmt.Println("Tools:")
	fmt.Println("  - get_pipeline_status: Get status of a CI/CD pipeline")
	fmt.Println("  - trigger_deployment: Trigger deployment to an environment")
	fmt.Println("  - rollback_deployment: Rollback deployment to a previous version")
	fmt.Println("  - get_error_logs: Get error logs for a service")
	fmt.Println("  - list_deployments: List recent deployments")
	fmt.Println("  - get_service_health: Get health status of services")
	fmt.Println("  - trigger_incident_report: Create an incident report for a service outage or issue")
	fmt.Println("  - get_service_status: Get detailed status of a specific service including recent errors")
	fmt.Println("Resources:")
	fmt.Println("  - pipeline://{pipeline_id}: Pipeline Details")
	fmt.Println("  - deployment://{deployment_id}: Deployment Details")
	fmt.Println("===================================")

	// Start StreamableHTTP server
	log.Println("Starting DevOps & CI Server Service on :8085")
	httpServer := server.NewStreamableHTTPServer(s)
	if err := httpServer.Start(":8085"); err != nil {
		log.Fatal(err)
	}
}

func handleGetPipelineStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pipelineID := req.GetString("pipeline_id", "")
	if pipelineID == "" {
		return nil, fmt.Errorf("pipeline_id is required")
	}

	// Get pipeline status
	pipeline, err := getPipelineFromRegistry(pipelineID)
	if err != nil {
		return nil, fmt.Errorf("pipeline not found: %s", pipelineID)
	}

	// Build stage JSON
	var stagesJSON string
	for i, stage := range pipeline.Stages {
		if i > 0 {
			stagesJSON += ","
		}
		stagesJSON += fmt.Sprintf(`{"name":"%s","status":"%s","duration":"%s","startTime":"%s"}`,
			stage.Name, stage.Status, stage.Duration, stage.StartTime.Format(time.RFC3339))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"id":"%s",
		"name":"%s",
		"status":"%s",
		"branch":"%s",
		"commit":"%s",
		"author":"%s",
		"startTime":"%s",
		"duration":"%s",
		"stages":[%s]
	}`,
		pipeline.ID, pipeline.Name, pipeline.Status, pipeline.Branch, pipeline.Commit,
		pipeline.Author, pipeline.StartTime.Format(time.RFC3339), pipeline.Duration, stagesJSON)), nil
}

func handleTriggerDeployment(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	env := req.GetString("env", "")
	service := req.GetString("service", "")
	version := req.GetString("version", "latest")

	if env == "" || service == "" {
		return nil, fmt.Errorf("env and service are required")
	}

	// Validate environment
	if !isValidEnvironment(env) {
		return nil, fmt.Errorf("invalid environment: %s. Must be one of: dev, staging, prod", env)
	}

	// Create deployment
	deployment := &Deployment{
		ID:        generateDeploymentID(),
		Service:   service,
		Version:   version,
		Env:       env,
		Status:    "In Progress",
		Author:    "CI System",
		StartTime: time.Now(),
		Logs: []LogEntry{
			{Message: "Deployment started", Timestamp: time.Now(), Level: "INFO"},
			{Message: fmt.Sprintf("Deploying %s version %s to %s", service, version, env), Timestamp: time.Now(), Level: "INFO"},
		},
	}

	// Simulate deployment progress
	go simulateDeployment(deployment)

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"deploymentId":"%s",
		"service":"%s",
		"version":"%s",
		"environment":"%s",
		"status":"In Progress",
		"message":"Deployment triggered successfully",
		"startTime":"%s"
	}`,
		deployment.ID, deployment.Service, deployment.Version, deployment.Env,
		deployment.StartTime.Format(time.RFC3339))), nil
}

func handleRollbackDeployment(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	env := req.GetString("env", "")
	version := req.GetString("version", "")
	service := req.GetString("service", "all")

	if env == "" || version == "" {
		return nil, fmt.Errorf("env and version are required")
	}

	// Validate environment
	if !isValidEnvironment(env) {
		return nil, fmt.Errorf("invalid environment: %s. Must be one of: dev, staging, prod", env)
	}

	// Create rollback deployment
	deployment := &Deployment{
		ID:        generateDeploymentID(),
		Service:   service,
		Version:   version,
		Env:       env,
		Status:    "Rolling Back",
		Author:    "CI System",
		StartTime: time.Now(),
		Logs: []LogEntry{
			{Message: "Rollback started", Timestamp: time.Now(), Level: "INFO"},
			{Message: fmt.Sprintf("Rolling back %s to version %s in %s", service, version, env), Timestamp: time.Now(), Level: "INFO"},
		},
	}

	// Simulate rollback
	go simulateRollback(deployment)

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"deploymentId":"%s",
		"service":"%s",
		"version":"%s",
		"environment":"%s",
		"status":"Rolling Back",
		"message":"Rollback initiated successfully",
		"startTime":"%s"
	}`,
		deployment.ID, deployment.Service, deployment.Version, deployment.Env,
		deployment.StartTime.Format(time.RFC3339))), nil
}

func handleGetErrorLogs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := req.GetString("service", "")
	since := req.GetString("since", "")
	env := req.GetString("env", "")

	if service == "" || since == "" {
		return nil, fmt.Errorf("service and since are required")
	}

	// Get error logs
	logs, err := getErrorLogsForService(service, since, env)
	if err != nil {
		return nil, fmt.Errorf("failed to get error logs: %w", err)
	}

	// Build logs JSON
	var logsJSON string
	for i, log := range logs {
		if i > 0 {
			logsJSON += ","
		}
		logsJSON += fmt.Sprintf(`{"timestamp":"%s","level":"%s","service":"%s","environment":"%s","message":"%s","trace":"%s"}`,
			log.Timestamp.Format(time.RFC3339), log.Level, log.Service, log.Environment, escapeJSON(log.Message), escapeJSON(log.Trace))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"service":"%s",
		"since":"%s",
		"environment":"%s",
		"totalErrors":%d,
		"logs":[%s]
	}`,
		service, since, env, len(logs), logsJSON)), nil
}

func handleListDeployments(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	env := req.GetString("env", "")
	service := req.GetString("service", "")
	limitStr := req.GetString("limit", "10")

	// Get deployments
	deployments, err := getRecentDeployments(env, service, limitStr)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployments: %w", err)
	}

	// Build deployments JSON
	var deploymentsJSON string
	for i, d := range deployments {
		if i > 0 {
			deploymentsJSON += ","
		}
		deploymentsJSON += fmt.Sprintf(`{"id":"%s","service":"%s","version":"%s","environment":"%s","status":"%s","author":"%s","startTime":"%s","duration":"%s"}`,
			d.ID, d.Service, d.Version, d.Env, d.Status, d.Author, d.StartTime.Format(time.RFC3339), d.Duration)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"deployments":[%s],
		"total":%d,
		"filters":{"environment":"%s","service":"%s","limit":"%s"}
	}`,
		deploymentsJSON, len(deployments), env, service, limitStr)), nil
}

func handleTriggerIncidentReport(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	title := req.GetString("title", "")
	description := req.GetString("description", "")
	severity := req.GetString("severity", "")
	affectedService := req.GetString("affected_service", "")
	environment := req.GetString("environment", "prod")

	if title == "" || description == "" || severity == "" || affectedService == "" {
		return nil, fmt.Errorf("title, description, severity, and affected_service are required")
	}

	if !isValidIncidentSeverity(severity) {
		return nil, fmt.Errorf("invalid severity: %s. Must be one of: low, medium, high, critical", severity)
	}

	// Create incident report
	incident := &Incident{
		ID:              generateIncidentID(),
		Title:           title,
		Description:     description,
		Severity:        severity,
		AffectedService: affectedService,
		Environment:     environment,
		Status:          "investigating",
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		Updates: []IncidentUpdate{
			{
				ID:        generateUpdateID(),
				Message:   "Incident report created",
				Status:    "investigating",
				Timestamp: time.Now(),
				Author:    "System",
			},
		},
	}

	if err := saveIncidentToRegistry(incident); err != nil {
		return nil, fmt.Errorf("failed to create incident: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"incidentId":"%s",
		"title":"%s",
		"severity":"%s",
		"affectedService":"%s",
		"environment":"%s",
		"status":"%s",
		"message":"Incident report created successfully",
		"createdAt":"%s"
	}`,
		incident.ID, incident.Title, incident.Severity, incident.AffectedService,
		incident.Environment, incident.Status, incident.CreatedAt.Format(time.RFC3339))), nil
}

func handleGetServiceStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := req.GetString("service", "")
	env := req.GetString("env", "prod")

	if service == "" {
		return nil, fmt.Errorf("service is required")
	}

	// Get detailed service status
	serviceStatus, err := getDetailedServiceStatus(service, env)
	if err != nil {
		return nil, fmt.Errorf("failed to get service status: %w", err)
	}

	// Build recent errors JSON
	var errorsJSON string
	for i, error := range serviceStatus.RecentErrors {
		if i > 0 {
			errorsJSON += ","
		}
		errorsJSON += fmt.Sprintf(`{"timestamp":"%s","level":"%s","message":"%s","count":%d}`,
			error.Timestamp.Format(time.RFC3339), error.Level, escapeJSON(error.Message), error.Count)
	}

	// Build metrics JSON
	var metricsJSON string
	for i, metric := range serviceStatus.Metrics {
		if i > 0 {
			metricsJSON += ","
		}
		metricsJSON += fmt.Sprintf(`{"name":"%s","value":"%s","status":"%s"}`,
			metric.Name, metric.Value, metric.Status)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"service":"%s",
		"environment":"%s",
		"status":"%s",
		"uptime":"%s",
		"lastHealthCheck":"%s",
		"version":"%s",
		"recentErrors":[%s],
		"metrics":[%s],
		"activeAlerts":%d,
		"description":"%s"
	}`,
		serviceStatus.Service, serviceStatus.Environment, serviceStatus.Status,
		serviceStatus.Uptime, serviceStatus.LastHealthCheck.Format(time.RFC3339),
		serviceStatus.Version, errorsJSON, metricsJSON, serviceStatus.ActiveAlerts,
		serviceStatus.Description)), nil
}

func handleGetServiceHealth(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	env := req.GetString("env", "")
	service := req.GetString("service", "")

	if env == "" {
		return nil, fmt.Errorf("env is required")
	}

	// Validate environment
	if !isValidEnvironment(env) {
		return nil, fmt.Errorf("invalid environment: %s. Must be one of: dev, staging, prod", env)
	}

	// Get service health
	healthData, err := getServiceHealthData(env, service)
	if err != nil {
		return nil, fmt.Errorf("failed to get service health: %w", err)
	}

	// Build services JSON
	var servicesJSON string
	for i, svc := range healthData {
		if i > 0 {
			servicesJSON += ","
		}
		servicesJSON += fmt.Sprintf(`{"name":"%s","status":"%s","uptime":"%s","responseTime":"%s","errorRate":"%.2f","lastCheck":"%s","version":"%s"}`,
			svc.Name, svc.Status, svc.Uptime, svc.ResponseTime, svc.ErrorRate, svc.LastCheck.Format(time.RFC3339), svc.Version)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"environment":"%s",
		"services":[%s],
		"totalServices":%d,
		"healthyServices":%d
	}`,
		env, servicesJSON, len(healthData), countHealthyServices(healthData))), nil
}

func handlePipelineResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	pipelineID := extractPipelineIDFromURI(req.Params.URI)

	pipeline, err := getPipelineFromRegistry(pipelineID)
	if err != nil {
		return nil, fmt.Errorf("pipeline not found: %s", pipelineID)
	}

	// Build stages JSON
	var stagesJSON string
	for i, stage := range pipeline.Stages {
		if i > 0 {
			stagesJSON += ","
		}
		stagesJSON += fmt.Sprintf(`{"name":"%s","status":"%s","duration":"%s","startTime":"%s","logs":"%s"}`,
			stage.Name, stage.Status, stage.Duration, stage.StartTime.Format(time.RFC3339), escapeJSON(stage.Logs))
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text: fmt.Sprintf(`{
				"id":"%s",
				"name":"%s",
				"status":"%s",
				"branch":"%s",
				"commit":"%s",
				"author":"%s",
				"startTime":"%s",
				"duration":"%s",
				"stages":[%s],
				"buildHistory":[%s]
			}`,
				pipeline.ID, pipeline.Name, pipeline.Status, pipeline.Branch, pipeline.Commit,
				pipeline.Author, pipeline.StartTime.Format(time.RFC3339), pipeline.Duration,
				stagesJSON, generateBuildHistory(pipeline.ID)),
		},
	}, nil
}

func handleDeploymentResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	deploymentID := extractDeploymentIDFromURI(req.Params.URI)

	deployment, err := getDeploymentFromRegistry(deploymentID)
	if err != nil {
		return nil, fmt.Errorf("deployment not found: %s", deploymentID)
	}

	// Build logs JSON
	var logsJSON string
	for i, log := range deployment.Logs {
		if i > 0 {
			logsJSON += ","
		}
		logsJSON += fmt.Sprintf(`{"message":"%s","timestamp":"%s","level":"%s"}`,
			escapeJSON(log.Message), log.Timestamp.Format(time.RFC3339), log.Level)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text: fmt.Sprintf(`{
				"id":"%s",
				"service":"%s",
				"version":"%s",
				"environment":"%s",
				"status":"%s",
				"author":"%s",
				"startTime":"%s",
				"endTime":"%s",
				"duration":"%s",
				"logs":[%s]
			}`,
				deployment.ID, deployment.Service, deployment.Version, deployment.Env,
				deployment.Status, deployment.Author, deployment.StartTime.Format(time.RFC3339),
				deployment.EndTime.Format(time.RFC3339), deployment.Duration, logsJSON),
		},
	}, nil
}

// Helper functions and types
type PipelineStage struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Duration  string    `json:"duration"`
	StartTime time.Time `json:"start_time"`
	Logs      string    `json:"logs"`
}

type Pipeline struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Status    string          `json:"status"`
	Branch    string          `json:"branch"`
	Commit    string          `json:"commit"`
	Author    string          `json:"author"`
	StartTime time.Time       `json:"start_time"`
	Duration  string          `json:"duration"`
	Stages    []PipelineStage `json:"stages"`
}

type LogEntry struct {
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	Level       string    `json:"level"`
	Service     string    `json:"service,omitempty"`
	Environment string    `json:"environment,omitempty"`
	Trace       string    `json:"trace,omitempty"`
}

type Deployment struct {
	ID        string     `json:"id"`
	Service   string     `json:"service"`
	Version   string     `json:"version"`
	Env       string     `json:"environment"`
	Status    string     `json:"status"`
	Author    string     `json:"author"`
	StartTime time.Time  `json:"start_time"`
	EndTime   time.Time  `json:"end_time"`
	Duration  string     `json:"duration"`
	Logs      []LogEntry `json:"logs"`
}

type ServiceHealth struct {
	Name         string    `json:"name"`
	Status       string    `json:"status"`
	Uptime       string    `json:"uptime"`
	ResponseTime string    `json:"response_time"`
	ErrorRate    float64   `json:"error_rate"`
	LastCheck    time.Time `json:"last_check"`
	Version      string    `json:"version"`
}

type IncidentUpdate struct {
	ID        string    `json:"id"`
	Message   string    `json:"message"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Author    string    `json:"author"`
}

type Incident struct {
	ID              string            `json:"id"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Severity        string            `json:"severity"`
	AffectedService string            `json:"affected_service"`
	Environment     string            `json:"environment"`
	Status          string            `json:"status"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	Updates         []IncidentUpdate  `json:"updates"`
}

type ServiceError struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Count     int       `json:"count"`
}

type ServiceMetric struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Status string `json:"status"`
}

type DetailedServiceStatus struct {
	Service         string          `json:"service"`
	Environment     string          `json:"environment"`
	Status          string          `json:"status"`
	Uptime          string          `json:"uptime"`
	LastHealthCheck time.Time       `json:"last_health_check"`
	Version         string          `json:"version"`
	RecentErrors    []ServiceError  `json:"recent_errors"`
	Metrics         []ServiceMetric `json:"metrics"`
	ActiveAlerts    int             `json:"active_alerts"`
	Description     string          `json:"description"`
}

type ErrorLog struct {
	Timestamp   time.Time `json:"timestamp"`
	Level       string    `json:"level"`
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Message     string    `json:"message"`
	Trace       string    `json:"trace"`
}

// Mock data storage (in a real implementation, this would be a database)
var mockPipelines = map[string]*Pipeline{
	"pipeline_1": {
		ID:        "pipeline_1",
		Name:      "frontend-build",
		Status:    "Success",
		Branch:    "main",
		Commit:    "abc123",
		Author:    "john.doe@company.com",
		StartTime: time.Now().Add(-45 * time.Minute),
		Duration:  "8m 32s",
		Stages: []PipelineStage{
			{Name: "Checkout", Status: "Success", Duration: "30s", StartTime: time.Now().Add(-45 * time.Minute), Logs: "Checked out code from main branch"},
			{Name: "Build", Status: "Success", Duration: "5m 12s", StartTime: time.Now().Add(-44 * time.Minute), Logs: "npm install && npm run build"},
			{Name: "Test", Status: "Success", Duration: "2m 45s", StartTime: time.Now().Add(-39 * time.Minute), Logs: "All tests passed (42 tests)"},
			{Name: "Deploy", Status: "Success", Duration: "5s", StartTime: time.Now().Add(-37 * time.Minute), Logs: "Deployed to staging environment"},
		},
	},
	"pipeline_2": {
		ID:        "pipeline_2",
		Name:      "backend-api",
		Status:    "Failed",
		Branch:    "feature/auth-service",
		Commit:    "def456",
		Author:    "jane.smith@company.com",
		StartTime: time.Now().Add(-2 * time.Hour),
		Duration:  "3m 18s",
		Stages: []PipelineStage{
			{Name: "Checkout", Status: "Success", Duration: "25s", StartTime: time.Now().Add(-2 * time.Hour), Logs: "Checked out code from feature branch"},
			{Name: "Build", Status: "Success", Duration: "1m 30s", StartTime: time.Now().Add(-119 * time.Minute), Logs: "go build completed successfully"},
			{Name: "Test", Status: "Failed", Duration: "1m 23s", StartTime: time.Now().Add(-118 * time.Minute), Logs: "ERROR: Test TestUserAuthentication failed - invalid JWT token"},
			{Name: "Deploy", Status: "Skipped", Duration: "0s", StartTime: time.Now().Add(-117 * time.Minute), Logs: "Skipped due to test failures"},
		},
	},
	"pipeline_3": {
		ID:        "pipeline_3",
		Name:      "database-migration",
		Status:    "In Progress",
		Branch:    "main",
		Commit:    "ghi789",
		Author:    "mike.johnson@company.com",
		StartTime: time.Now().Add(-10 * time.Minute),
		Duration:  "running",
		Stages: []PipelineStage{
			{Name: "Checkout", Status: "Success", Duration: "20s", StartTime: time.Now().Add(-10 * time.Minute), Logs: "Checked out migration scripts"},
			{Name: "Validate", Status: "Success", Duration: "45s", StartTime: time.Now().Add(-9 * time.Minute), Logs: "Migration scripts validated"},
			{Name: "Backup", Status: "In Progress", Duration: "running", StartTime: time.Now().Add(-8 * time.Minute), Logs: "Creating database backup..."},
			{Name: "Migrate", Status: "Pending", Duration: "pending", StartTime: time.Now().Add(-8 * time.Minute), Logs: "Waiting for backup to complete"},
		},
	},
}

var mockDeployments = []*Deployment{
	{
		ID:        "deploy_1",
		Service:   "user-service",
		Version:   "v1.2.3",
		Env:       "prod",
		Status:    "Success",
		Author:    "CI System",
		StartTime: time.Now().Add(-3 * time.Hour),
		EndTime:   time.Now().Add(-2*time.Hour - 45*time.Minute),
		Duration:  "15m 22s",
		Logs: []LogEntry{
			{Message: "Deployment started", Timestamp: time.Now().Add(-3 * time.Hour), Level: "INFO"},
			{Message: "Health check passed", Timestamp: time.Now().Add(-2*time.Hour - 50*time.Minute), Level: "INFO"},
			{Message: "Deployment completed successfully", Timestamp: time.Now().Add(-2*time.Hour - 45*time.Minute), Level: "INFO"},
		},
	},
	{
		ID:        "deploy_2",
		Service:   "payment-service",
		Version:   "v2.1.0",
		Env:       "staging",
		Status:    "Failed",
		Author:    "alice.brown@company.com",
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now().Add(-45 * time.Minute),
		Duration:  "15m 0s",
		Logs: []LogEntry{
			{Message: "Deployment started", Timestamp: time.Now().Add(-1 * time.Hour), Level: "INFO"},
			{Message: "Service failed to start - port 8080 already in use", Timestamp: time.Now().Add(-45 * time.Minute), Level: "ERROR"},
			{Message: "Deployment failed", Timestamp: time.Now().Add(-45 * time.Minute), Level: "ERROR"},
		},
	},
}

func getPipelineFromRegistry(pipelineID string) (*Pipeline, error) {
	if pipeline, exists := mockPipelines[pipelineID]; exists {
		return pipeline, nil
	}
	return nil, fmt.Errorf("pipeline not found")
}

func getDeploymentFromRegistry(deploymentID string) (*Deployment, error) {
	for _, deployment := range mockDeployments {
		if deployment.ID == deploymentID {
			return deployment, nil
		}
	}
	return nil, fmt.Errorf("deployment not found")
}

func isValidEnvironment(env string) bool {
	return env == "dev" || env == "staging" || env == "prod"
}

func generateDeploymentID() string {
	return fmt.Sprintf("deploy_%d", time.Now().UnixNano())
}

func simulateDeployment(deployment *Deployment) {
	// Simulate deployment taking some time
	time.Sleep(2 * time.Second)
	deployment.Status = "Success"
	deployment.EndTime = time.Now()
	deployment.Duration = deployment.EndTime.Sub(deployment.StartTime).String()
	deployment.Logs = append(deployment.Logs, LogEntry{
		Message:   "Deployment completed successfully",
		Timestamp: time.Now(),
		Level:     "INFO",
	})

	// Add to mock deployments
	mockDeployments = append(mockDeployments, deployment)
}

func simulateRollback(deployment *Deployment) {
	// Simulate rollback taking some time
	time.Sleep(1 * time.Second)
	deployment.Status = "Rolled Back"
	deployment.EndTime = time.Now()
	deployment.Duration = deployment.EndTime.Sub(deployment.StartTime).String()
	deployment.Logs = append(deployment.Logs, LogEntry{
		Message:   "Rollback completed successfully",
		Timestamp: time.Now(),
		Level:     "INFO",
	})

	// Add to mock deployments
	mockDeployments = append(mockDeployments, deployment)
}

func getErrorLogsForService(service, since, env string) ([]ErrorLog, error) {
	// Mock error logs data
	logs := []ErrorLog{
		{
			Timestamp:   time.Now().Add(-30 * time.Minute),
			Level:       "ERROR",
			Service:     service,
			Environment: "prod",
			Message:     "Database connection timeout after 30 seconds",
			Trace:       "at DatabaseConnection.connect(database.go:45)\nat UserService.GetUser(user.go:123)",
		},
		{
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Level:       "ERROR",
			Service:     service,
			Environment: "prod",
			Message:     "Failed to validate JWT token: token expired",
			Trace:       "at AuthMiddleware.ValidateToken(auth.go:67)\nat UserController.GetProfile(controller.go:89)",
		},
		{
			Timestamp:   time.Now().Add(-2 * time.Hour),
			Level:       "WARN",
			Service:     service,
			Environment: "staging",
			Message:     "High memory usage detected: 85% of available memory",
			Trace:       "",
		},
		{
			Timestamp:   time.Now().Add(-3 * time.Hour),
			Level:       "ERROR",
			Service:     service,
			Environment: "prod",
			Message:     "External API call failed: 503 Service Unavailable",
			Trace:       "at PaymentAPI.ProcessPayment(payment.go:156)\nat OrderService.CompleteOrder(order.go:234)",
		},
		{
			Timestamp:   time.Now().Add(-4 * time.Hour),
			Level:       "ERROR",
			Service:     service,
			Environment: "dev",
			Message:     "Redis cache connection lost",
			Trace:       "at CacheService.Get(cache.go:78)\nat ProductService.GetProducts(product.go:45)",
		},
	}

	// Filter by environment if specified
	filtered := []ErrorLog{}
	for _, log := range logs {
		if env == "" || log.Environment == env {
			filtered = append(filtered, log)
		}
	}

	return filtered, nil
}

func getRecentDeployments(env, service, limitStr string) ([]*Deployment, error) {
	deployments := mockDeployments

	// Filter by environment and service
	filtered := []*Deployment{}
	for _, d := range deployments {
		if (env == "" || d.Env == env) && (service == "" || d.Service == service) {
			filtered = append(filtered, d)
		}
	}

	// Apply limit (simplified)
	if len(filtered) > 10 {
		filtered = filtered[:10]
	}

	return filtered, nil
}

func getServiceHealthData(env, service string) ([]ServiceHealth, error) {
	allServices := []ServiceHealth{
		{
			Name:         "user-service",
			Status:       "Healthy",
			Uptime:       "99.8%",
			ResponseTime: "145ms",
			ErrorRate:    0.02,
			LastCheck:    time.Now().Add(-1 * time.Minute),
			Version:      "v1.2.3",
		},
		{
			Name:         "payment-service",
			Status:       "Degraded",
			Uptime:       "97.2%",
			ResponseTime: "890ms",
			ErrorRate:    2.1,
			LastCheck:    time.Now().Add(-30 * time.Second),
			Version:      "v2.1.0",
		},
		{
			Name:         "inventory-service",
			Status:       "Healthy",
			Uptime:       "99.9%",
			ResponseTime: "67ms",
			ErrorRate:    0.01,
			LastCheck:    time.Now().Add(-45 * time.Second),
			Version:      "v1.5.2",
		},
		{
			Name:         "notification-service",
			Status:       "Down",
			Uptime:       "0%",
			ResponseTime: "timeout",
			ErrorRate:    100.0,
			LastCheck:    time.Now().Add(-5 * time.Minute),
			Version:      "v1.0.8",
		},
		{
			Name:         "analytics-service",
			Status:       "Healthy",
			Uptime:       "99.5%",
			ResponseTime: "234ms",
			ErrorRate:    0.5,
			LastCheck:    time.Now().Add(-2 * time.Minute),
			Version:      "v3.1.1",
		},
	}

	// Filter by service if specified
	if service != "" {
		for _, svc := range allServices {
			if svc.Name == service {
				return []ServiceHealth{svc}, nil
			}
		}
		return []ServiceHealth{}, nil
	}

	return allServices, nil
}

func countHealthyServices(services []ServiceHealth) int {
	count := 0
	for _, svc := range services {
		if svc.Status == "Healthy" {
			count++
		}
	}
	return count
}

func extractPipelineIDFromURI(uri string) string {
	if len(uri) > 11 && uri[:11] == "pipeline://" {
		return uri[11:]
	}
	return uri
}

func extractDeploymentIDFromURI(uri string) string {
	if len(uri) > 13 && uri[:13] == "deployment://" {
		return uri[13:]
	}
	return uri
}

func generateBuildHistory(pipelineID string) string {
	// Generate mock build history
	history := []string{
		`{"buildNumber":15,"status":"Success","date":"2024-01-15T10:30:00Z","commit":"abc123"}`,
		`{"buildNumber":14,"status":"Failed","date":"2024-01-14T16:20:00Z","commit":"xyz789"}`,
		`{"buildNumber":13,"status":"Success","date":"2024-01-14T09:15:00Z","commit":"def456"}`,
	}
	return strings.Join(history, ",")
}

// Mock incident storage
var mockIncidents = map[string]*Incident{}

// Mock detailed service status for demo
var mockDetailedServiceStatus = map[string]*DetailedServiceStatus{
	"pdf-gen-service": {
		Service:         "pdf-gen-service",
		Environment:     "prod",
		Status:          "degraded",
		Uptime:          "97.2%",
		LastHealthCheck: time.Now().Add(-30 * time.Second),
		Version:         "v2.3.1",
		RecentErrors: []ServiceError{
			{
				Timestamp: time.Now().Add(-15 * time.Minute),
				Level:     "ERROR",
				Message:   "Gateway timeout processing large document",
				Count:     23,
			},
			{
				Timestamp: time.Now().Add(-45 * time.Minute),
				Level:     "ERROR", 
				Message:   "502 Bad Gateway - upstream server timeout",
				Count:     67,
			},
			{
				Timestamp: time.Now().Add(-1 * time.Hour),
				Level:     "WARN",
				Message:   "High memory usage detected: 89% of available memory",
				Count:     12,
			},
		},
		Metrics: []ServiceMetric{
			{Name: "response_time", Value: "1.8s", Status: "warning"},
			{Name: "error_rate", Value: "12.3%", Status: "critical"},
			{Name: "memory_usage", Value: "89%", Status: "warning"},
			{Name: "cpu_usage", Value: "45%", Status: "healthy"},
			{Name: "active_connections", Value: "245", Status: "healthy"},
		},
		ActiveAlerts:    3,
		Description:     "PDF generation service experiencing issues with large document processing",
	},
	"user-service": {
		Service:         "user-service",
		Environment:     "prod",
		Status:          "healthy",
		Uptime:          "99.8%",
		LastHealthCheck: time.Now().Add(-1 * time.Minute),
		Version:         "v1.2.3",
		RecentErrors: []ServiceError{
			{
				Timestamp: time.Now().Add(-2 * time.Hour),
				Level:     "WARN",
				Message:   "Slow query detected on user lookup",
				Count:     3,
			},
		},
		Metrics: []ServiceMetric{
			{Name: "response_time", Value: "145ms", Status: "healthy"},
			{Name: "error_rate", Value: "0.02%", Status: "healthy"},
			{Name: "memory_usage", Value: "67%", Status: "healthy"},
			{Name: "cpu_usage", Value: "23%", Status: "healthy"},
			{Name: "active_connections", Value: "1,234", Status: "healthy"},
		},
		ActiveAlerts:    0,
		Description:     "User authentication and management service running normally",
	},
}

func isValidIncidentSeverity(severity string) bool {
	return severity == "low" || severity == "medium" || severity == "high" || severity == "critical"
}

func generateIncidentID() string {
	return fmt.Sprintf("incident_%d", time.Now().UnixNano())
}

func generateUpdateID() string {
	return fmt.Sprintf("update_%d", time.Now().UnixNano())
}

func saveIncidentToRegistry(incident *Incident) error {
	mockIncidents[incident.ID] = incident
	return nil
}

func getDetailedServiceStatus(service, env string) (*DetailedServiceStatus, error) {
	if status, exists := mockDetailedServiceStatus[service]; exists {
		// Create a copy with the requested environment
		statusCopy := *status
		statusCopy.Environment = env
		return &statusCopy, nil
	}
	
	// Return a default status for unknown services
	return &DetailedServiceStatus{
		Service:         service,
		Environment:     env,
		Status:          "unknown",
		Uptime:          "N/A",
		LastHealthCheck: time.Now(),
		Version:         "unknown",
		RecentErrors:    []ServiceError{},
		Metrics:         []ServiceMetric{},
		ActiveAlerts:    0,
		Description:     fmt.Sprintf("No monitoring data available for %s", service),
	}, nil
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}
