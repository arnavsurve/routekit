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
	s := server.NewMCPServer("Bug Tracker Service", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	)

	// Add Bug Tracker tools
	s.AddTool(
		mcp.NewTool("create_bug",
			mcp.WithDescription("Create a new bug report"),
			mcp.WithString("summary", mcp.Required(), mcp.Description("Brief summary of the bug")),
			mcp.WithString("description", mcp.Required(), mcp.Description("Detailed description of the bug")),
			mcp.WithString("severity", mcp.Required(), mcp.Description("Bug severity (low, medium, high, critical)")),
			mcp.WithString("component", mcp.Description("Affected component or service")),
			mcp.WithString("reproduction_steps", mcp.Description("Steps to reproduce the issue")),
		),
		handleCreateBug,
	)

	s.AddTool(
		mcp.NewTool("assign_bug",
			mcp.WithDescription("Assign a bug to a developer or team"),
			mcp.WithString("bug_id", mcp.Required(), mcp.Description("Bug ID to assign")),
			mcp.WithString("assignee", mcp.Required(), mcp.Description("Developer or team to assign to")),
		),
		handleAssignBug,
	)

	s.AddTool(
		mcp.NewTool("search_bugs",
			mcp.WithDescription("Search bugs with optional filters"),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search query for bug title or description")),
			mcp.WithString("status", mcp.Description("Filter by status (open, in_progress, resolved, closed)")),
			mcp.WithString("severity", mcp.Description("Filter by severity (low, medium, high, critical)")),
			mcp.WithString("assignee", mcp.Description("Filter by assigned developer or team")),
		),
		handleSearchBugs,
	)

	s.AddTool(
		mcp.NewTool("update_bug_status",
			mcp.WithDescription("Update the status of a bug"),
			mcp.WithString("bug_id", mcp.Required(), mcp.Description("Bug ID to update")),
			mcp.WithString("status", mcp.Required(), mcp.Description("New status (open, in_progress, resolved, closed)")),
			mcp.WithString("comment", mcp.Description("Optional comment about the status change")),
		),
		handleUpdateBugStatus,
	)

	s.AddTool(
		mcp.NewTool("link_ticket_to_bug",
			mcp.WithDescription("Link a support ticket to a bug report"),
			mcp.WithString("bug_id", mcp.Required(), mcp.Description("Bug ID to link to")),
			mcp.WithString("ticket_id", mcp.Required(), mcp.Description("Support ticket ID to link")),
		),
		handleLinkTicketToBug,
	)

	s.AddTool(
		mcp.NewTool("get_bug_details",
			mcp.WithDescription("Get detailed information about a bug"),
			mcp.WithString("bug_id", mcp.Required(), mcp.Description("Bug ID to retrieve")),
		),
		handleGetBugDetails,
	)

	s.AddTool(
		mcp.NewTool("get_team_bugs",
			mcp.WithDescription("Get bugs assigned to a specific team"),
			mcp.WithString("team", mcp.Required(), mcp.Description("Team name to get bugs for")),
			mcp.WithString("status", mcp.Description("Filter by status (optional)")),
		),
		handleGetTeamBugs,
	)

	// Add resources
	s.AddResource(
		mcp.NewResource(
			"bug://{bug_id}",
			"Bug Report",
			mcp.WithResourceDescription("Complete bug report with comments and linked tickets"),
			mcp.WithMIMEType("application/json"),
		),
		handleBugResource,
	)

	// Print capabilities
	fmt.Println("=== Bug Tracker Service Capabilities ===")
	fmt.Println("Tools:")
	fmt.Println("  - create_bug: Create a new bug report")
	fmt.Println("  - assign_bug: Assign a bug to a developer or team")
	fmt.Println("  - search_bugs: Search bugs with optional filters")
	fmt.Println("  - update_bug_status: Update the status of a bug")
	fmt.Println("  - link_ticket_to_bug: Link a support ticket to a bug report")
	fmt.Println("  - get_bug_details: Get detailed information about a bug")
	fmt.Println("  - get_team_bugs: Get bugs assigned to a specific team")
	fmt.Println("Resources:")
	fmt.Println("  - bug://{bug_id}: Bug Report")
	fmt.Println("===================================")

	// Start StreamableHTTP server
	log.Println("Starting Bug Tracker Service on :8087")
	httpServer := server.NewStreamableHTTPServer(s)
	if err := httpServer.Start(":8087"); err != nil {
		log.Fatal(err)
	}
}

func handleCreateBug(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	summary := req.GetString("summary", "")
	description := req.GetString("description", "")
	severity := req.GetString("severity", "")
	component := req.GetString("component", "")
	reproductionSteps := req.GetString("reproduction_steps", "")

	if summary == "" || description == "" || severity == "" {
		return nil, fmt.Errorf("summary, description, and severity are required")
	}

	if !isValidSeverity(severity) {
		return nil, fmt.Errorf("invalid severity: %s. Must be one of: low, medium, high, critical", severity)
	}

	// Create new bug
	bug := &Bug{
		ID:               generateBugID(),
		Summary:          summary,
		Description:      description,
		Severity:         severity,
		Status:           "open",
		Component:        component,
		ReproductionSteps: reproductionSteps,
		Reporter:         "System",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		Comments: []Comment{
			{
				ID:        generateCommentID(),
				Author:    "System",
				Content:   "Bug report created",
				Timestamp: time.Now(),
			},
		},
	}

	if err := saveBugToRegistry(bug); err != nil {
		return nil, fmt.Errorf("failed to create bug: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"bugId":"%s",
		"summary":"%s",
		"severity":"%s",
		"status":"%s",
		"message":"Bug created successfully",
		"createdAt":"%s"
	}`,
		bug.ID, bug.Summary, bug.Severity, bug.Status, bug.CreatedAt.Format(time.RFC3339))), nil
}

func handleAssignBug(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	bugID := req.GetString("bug_id", "")
	assignee := req.GetString("assignee", "")

	if bugID == "" || assignee == "" {
		return nil, fmt.Errorf("bug_id and assignee are required")
	}

	bug, err := getBugFromRegistry(bugID)
	if err != nil {
		return nil, fmt.Errorf("bug not found: %s", bugID)
	}

	oldAssignee := bug.Assignee
	bug.Assignee = assignee
	bug.UpdatedAt = time.Now()
	if bug.Status == "open" {
		bug.Status = "in_progress"
	}

	// Add comment about assignment
	comment := Comment{
		ID:        generateCommentID(),
		Author:    "System",
		Content:   fmt.Sprintf("Bug assigned to %s", assignee),
		Timestamp: time.Now(),
	}
	bug.Comments = append(bug.Comments, comment)

	if err := updateBugInRegistry(bug); err != nil {
		return nil, fmt.Errorf("failed to assign bug: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"bugId":"%s",
		"message":"Bug assigned successfully",
		"previousAssignee":"%s",
		"currentAssignee":"%s",
		"status":"%s",
		"updatedAt":"%s"
	}`,
		bug.ID, oldAssignee, bug.Assignee, bug.Status, bug.UpdatedAt.Format(time.RFC3339))), nil
}

func handleSearchBugs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	status := req.GetString("status", "")
	severity := req.GetString("severity", "")
	assignee := req.GetString("assignee", "")

	if query == "" {
		return nil, fmt.Errorf("query is required")
	}

	bugs, err := searchBugsInRegistry(query, status, severity, assignee)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Build bugs JSON
	var bugsJSON string
	for i, b := range bugs {
		if i > 0 {
			bugsJSON += ","
		}
		bugsJSON += fmt.Sprintf(`{"id":"%s","summary":"%s","severity":"%s","status":"%s","assignee":"%s","component":"%s","updatedAt":"%s"}`,
			b.ID, b.Summary, b.Severity, b.Status, b.Assignee, b.Component, b.UpdatedAt.Format(time.RFC3339))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"bugs":[%s],
		"total":%d,
		"query":"%s",
		"filters":{"status":"%s","severity":"%s","assignee":"%s"}
	}`,
		bugsJSON, len(bugs), query, status, severity, assignee)), nil
}

func handleUpdateBugStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	bugID := req.GetString("bug_id", "")
	status := req.GetString("status", "")
	comment := req.GetString("comment", "")

	if bugID == "" || status == "" {
		return nil, fmt.Errorf("bug_id and status are required")
	}

	if !isValidStatus(status) {
		return nil, fmt.Errorf("invalid status: %s. Must be one of: open, in_progress, resolved, closed", status)
	}

	bug, err := getBugFromRegistry(bugID)
	if err != nil {
		return nil, fmt.Errorf("bug not found: %s", bugID)
	}

	oldStatus := bug.Status
	bug.Status = status
	bug.UpdatedAt = time.Now()

	// Add comment about status change
	commentText := fmt.Sprintf("Status changed from %s to %s", oldStatus, status)
	if comment != "" {
		commentText += fmt.Sprintf(". %s", comment)
	}

	statusComment := Comment{
		ID:        generateCommentID(),
		Author:    "System",
		Content:   commentText,
		Timestamp: time.Now(),
	}
	bug.Comments = append(bug.Comments, statusComment)

	if err := updateBugInRegistry(bug); err != nil {
		return nil, fmt.Errorf("failed to update bug status: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"bugId":"%s",
		"message":"Bug status updated successfully",
		"previousStatus":"%s",
		"currentStatus":"%s",
		"updatedAt":"%s"
	}`,
		bug.ID, oldStatus, bug.Status, bug.UpdatedAt.Format(time.RFC3339))), nil
}

func handleLinkTicketToBug(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	bugID := req.GetString("bug_id", "")
	ticketID := req.GetString("ticket_id", "")

	if bugID == "" || ticketID == "" {
		return nil, fmt.Errorf("bug_id and ticket_id are required")
	}

	bug, err := getBugFromRegistry(bugID)
	if err != nil {
		return nil, fmt.Errorf("bug not found: %s", bugID)
	}

	// Check if already linked
	for _, linkedTicket := range bug.LinkedTickets {
		if linkedTicket == ticketID {
			return nil, fmt.Errorf("ticket %s is already linked to bug %s", ticketID, bugID)
		}
	}

	// Add ticket link
	bug.LinkedTickets = append(bug.LinkedTickets, ticketID)
	bug.UpdatedAt = time.Now()

	// Add comment about linking
	linkComment := Comment{
		ID:        generateCommentID(),
		Author:    "System",
		Content:   fmt.Sprintf("Linked to support ticket %s", ticketID),
		Timestamp: time.Now(),
	}
	bug.Comments = append(bug.Comments, linkComment)

	if err := updateBugInRegistry(bug); err != nil {
		return nil, fmt.Errorf("failed to link ticket to bug: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"bugId":"%s",
		"ticketId":"%s",
		"message":"Ticket linked to bug successfully",
		"linkedTickets":%d,
		"updatedAt":"%s"
	}`,
		bug.ID, ticketID, len(bug.LinkedTickets), bug.UpdatedAt.Format(time.RFC3339))), nil
}

func handleGetBugDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	bugID := req.GetString("bug_id", "")
	if bugID == "" {
		return nil, fmt.Errorf("bug_id is required")
	}

	bug, err := getBugFromRegistry(bugID)
	if err != nil {
		return nil, fmt.Errorf("bug not found: %s", bugID)
	}

	// Build comments JSON
	var commentsJSON string
	for i, comment := range bug.Comments {
		if i > 0 {
			commentsJSON += ","
		}
		commentsJSON += fmt.Sprintf(`{"id":"%s","author":"%s","content":"%s","timestamp":"%s"}`,
			comment.ID, comment.Author, escapeJSON(comment.Content), comment.Timestamp.Format(time.RFC3339))
	}

	// Build linked tickets JSON
	var ticketsJSON string
	for i, ticket := range bug.LinkedTickets {
		if i > 0 {
			ticketsJSON += ","
		}
		ticketsJSON += fmt.Sprintf(`"%s"`, ticket)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"id":"%s",
		"summary":"%s",
		"description":"%s",
		"severity":"%s",
		"status":"%s",
		"component":"%s",
		"assignee":"%s",
		"reporter":"%s",
		"createdAt":"%s",
		"updatedAt":"%s",
		"reproductionSteps":"%s",
		"comments":[%s],
		"linkedTickets":[%s]
	}`,
		bug.ID, bug.Summary, escapeJSON(bug.Description), bug.Severity, bug.Status,
		bug.Component, bug.Assignee, bug.Reporter, bug.CreatedAt.Format(time.RFC3339),
		bug.UpdatedAt.Format(time.RFC3339), escapeJSON(bug.ReproductionSteps),
		commentsJSON, ticketsJSON)), nil
}

func handleGetTeamBugs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	team := req.GetString("team", "")
	status := req.GetString("status", "")

	if team == "" {
		return nil, fmt.Errorf("team is required")
	}

	bugs, err := getTeamBugsFromRegistry(team, status)
	if err != nil {
		return nil, fmt.Errorf("failed to get team bugs: %w", err)
	}

	// Build bugs JSON
	var bugsJSON string
	for i, b := range bugs {
		if i > 0 {
			bugsJSON += ","
		}
		bugsJSON += fmt.Sprintf(`{"id":"%s","summary":"%s","severity":"%s","status":"%s","component":"%s","updatedAt":"%s"}`,
			b.ID, b.Summary, b.Severity, b.Status, b.Component, b.UpdatedAt.Format(time.RFC3339))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"team":"%s",
		"bugs":[%s],
		"total":%d,
		"statusFilter":"%s"
	}`,
		team, bugsJSON, len(bugs), status)), nil
}

func handleBugResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	bugID := extractBugIDFromURI(req.Params.URI)

	bug, err := getBugFromRegistry(bugID)
	if err != nil {
		return nil, fmt.Errorf("bug not found: %s", bugID)
	}

	// Build complete bug JSON
	var commentsJSON string
	for i, comment := range bug.Comments {
		if i > 0 {
			commentsJSON += ","
		}
		commentsJSON += fmt.Sprintf(`{"id":"%s","author":"%s","content":"%s","timestamp":"%s"}`,
			comment.ID, comment.Author, escapeJSON(comment.Content), comment.Timestamp.Format(time.RFC3339))
	}

	var ticketsJSON string
	for i, ticket := range bug.LinkedTickets {
		if i > 0 {
			ticketsJSON += ","
		}
		ticketsJSON += fmt.Sprintf(`"%s"`, ticket)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text: fmt.Sprintf(`{
				"id":"%s",
				"summary":"%s",
				"description":"%s",
				"severity":"%s",
				"status":"%s",
				"component":"%s",
				"assignee":"%s",
				"reporter":"%s",
				"createdAt":"%s",
				"updatedAt":"%s",
				"reproductionSteps":"%s",
				"comments":[%s],
				"linkedTickets":[%s],
				"metadata":{"totalComments":%d,"totalLinkedTickets":%d}
			}`,
				bug.ID, bug.Summary, escapeJSON(bug.Description), bug.Severity, bug.Status,
				bug.Component, bug.Assignee, bug.Reporter, bug.CreatedAt.Format(time.RFC3339),
				bug.UpdatedAt.Format(time.RFC3339), escapeJSON(bug.ReproductionSteps),
				commentsJSON, ticketsJSON, len(bug.Comments), len(bug.LinkedTickets)),
		},
	}, nil
}

// Helper functions and types
type Comment struct {
	ID        string    `json:"id"`
	Author    string    `json:"author"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

type Bug struct {
	ID                string    `json:"id"`
	Summary           string    `json:"summary"`
	Description       string    `json:"description"`
	Severity          string    `json:"severity"`
	Status            string    `json:"status"`
	Component         string    `json:"component"`
	Assignee          string    `json:"assignee"`
	Reporter          string    `json:"reporter"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	ReproductionSteps string    `json:"reproduction_steps"`
	Comments          []Comment `json:"comments"`
	LinkedTickets     []string  `json:"linked_tickets"`
}

// Mock bug data for demo scenario
var mockBugs = map[string]*Bug{
	"bug_1": {
		ID:          "bug_1",
		Summary:     "PDF generation service returning 502 errors",
		Description: "The pdf-gen service is returning 502 Bad Gateway errors when processing documents larger than 10MB. This is affecting multiple customers including high-value accounts.",
		Severity:    "high",
		Status:      "in_progress",
		Component:   "pdf-gen-service",
		Assignee:    "Docs Infra Team",
		Reporter:    "Support System",
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		UpdatedAt:   time.Now().Add(-30 * time.Minute),
		ReproductionSteps: "1. Upload document > 10MB to pdf-gen API\n2. Observe 502 error response\n3. Check service logs for gateway timeout",
		Comments: []Comment{
			{
				ID:        "comment_1",
				Author:    "Support System",
				Content:   "Bug report created from customer outage report",
				Timestamp: time.Now().Add(-2 * time.Hour),
			},
			{
				ID:        "comment_2",
				Author:    "System",
				Content:   "Bug assigned to Docs Infra Team",
				Timestamp: time.Now().Add(-1*time.Hour - 45*time.Minute),
			},
			{
				ID:        "comment_3",
				Author:    "Alex Rodriguez",
				Content:   "Investigating the issue. Appears to be a timeout in the document processing pipeline when handling large files.",
				Timestamp: time.Now().Add(-30 * time.Minute),
			},
		},
		LinkedTickets: []string{"ticket_1"},
	},
	"bug_2": {
		ID:          "bug_2",
		Summary:     "Memory leak in user authentication service",
		Description: "The auth service shows steadily increasing memory usage over time, eventually leading to OOM crashes.",
		Severity:    "medium",
		Status:      "open",
		Component:   "auth-service",
		Assignee:    "Backend Team",
		Reporter:    "DevOps",
		CreatedAt:   time.Now().Add(-5 * 24 * time.Hour),
		UpdatedAt:   time.Now().Add(-3 * 24 * time.Hour),
		ReproductionSteps: "1. Monitor auth service memory usage over 24+ hours\n2. Observe gradual memory increase\n3. Service crashes with OOM error",
		Comments: []Comment{
			{
				ID:        "comment_4",
				Author:    "DevOps",
				Content:   "Memory usage has increased 300% over the past week",
				Timestamp: time.Now().Add(-5 * 24 * time.Hour),
			},
			{
				ID:        "comment_5",
				Author:    "Backend Team",
				Content:   "Will investigate JWT token cache implementation",
				Timestamp: time.Now().Add(-3 * 24 * time.Hour),
			},
		},
		LinkedTickets: []string{},
	},
}

func getBugFromRegistry(bugID string) (*Bug, error) {
	if bug, exists := mockBugs[bugID]; exists {
		return bug, nil
	}
	return nil, fmt.Errorf("bug not found")
}

func saveBugToRegistry(bug *Bug) error {
	mockBugs[bug.ID] = bug
	return nil
}

func updateBugInRegistry(bug *Bug) error {
	mockBugs[bug.ID] = bug
	return nil
}

func searchBugsInRegistry(query, status, severity, assignee string) ([]*Bug, error) {
	var results []*Bug
	queryLower := strings.ToLower(query)

	for _, bug := range mockBugs {
		// Check if bug matches search criteria
		matches := false
		
		if strings.Contains(strings.ToLower(bug.Summary), queryLower) ||
			strings.Contains(strings.ToLower(bug.Description), queryLower) ||
			strings.Contains(strings.ToLower(bug.Component), queryLower) {
			matches = true
		}

		if !matches {
			continue
		}

		// Apply filters
		if status != "" && bug.Status != status {
			continue
		}
		if severity != "" && bug.Severity != severity {
			continue
		}
		if assignee != "" && bug.Assignee != assignee {
			continue
		}

		results = append(results, bug)
	}

	return results, nil
}

func getTeamBugsFromRegistry(team, status string) ([]*Bug, error) {
	var results []*Bug

	for _, bug := range mockBugs {
		if bug.Assignee == team || strings.Contains(bug.Assignee, team) {
			if status == "" || bug.Status == status {
				results = append(results, bug)
			}
		}
	}

	return results, nil
}

func isValidSeverity(severity string) bool {
	return severity == "low" || severity == "medium" || severity == "high" || severity == "critical"
}

func isValidStatus(status string) bool {
	return status == "open" || status == "in_progress" || status == "resolved" || status == "closed"
}

func generateBugID() string {
	return fmt.Sprintf("bug_%d", time.Now().UnixNano())
}

func generateCommentID() string {
	return fmt.Sprintf("comment_%d", time.Now().UnixNano())
}

func extractBugIDFromURI(uri string) string {
	if len(uri) > 6 && uri[:6] == "bug://" {
		return uri[6:]
	}
	return uri
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}