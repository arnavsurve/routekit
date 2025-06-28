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
	s := server.NewMCPServer("Customer Support Service", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	)

	// Add Customer Support tools
	s.AddTool(
		mcp.NewTool("get_ticket",
			mcp.WithDescription("Get detailed information about a support ticket"),
			mcp.WithString("id", mcp.Required(), mcp.Description("Ticket ID to retrieve")),
		),
		handleGetTicket,
	)

	s.AddTool(
		mcp.NewTool("search_tickets",
			mcp.WithDescription("Search support tickets with optional filters"),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search query for ticket content, customer, or subject")),
			mcp.WithString("status", mcp.Description("Filter by ticket status (open, pending, solved, closed)")),
			mcp.WithString("priority", mcp.Description("Filter by priority (low, normal, high, urgent)")),
			mcp.WithString("assigned_to", mcp.Description("Filter by assigned agent")),
		),
		handleSearchTickets,
	)

	s.AddTool(
		mcp.NewTool("reply_to_ticket",
			mcp.WithDescription("Add a reply to a support ticket"),
			mcp.WithString("id", mcp.Required(), mcp.Description("Ticket ID to reply to")),
			mcp.WithString("message", mcp.Required(), mcp.Description("Reply message content")),
			mcp.WithString("is_public", mcp.Description("Whether reply is public (true) or internal note (false). Defaults to true")),
		),
		handleReplyToTicket,
	)

	s.AddTool(
		mcp.NewTool("close_ticket",
			mcp.WithDescription("Close a support ticket"),
			mcp.WithString("id", mcp.Required(), mcp.Description("Ticket ID to close")),
			mcp.WithString("resolution", mcp.Description("Resolution summary (optional)")),
		),
		handleCloseTicket,
	)

	s.AddTool(
		mcp.NewTool("update_ticket_priority",
			mcp.WithDescription("Update the priority of a support ticket"),
			mcp.WithString("id", mcp.Required(), mcp.Description("Ticket ID to update")),
			mcp.WithString("priority", mcp.Required(), mcp.Description("New priority (low, normal, high, urgent)")),
		),
		handleUpdateTicketPriority,
	)

	s.AddTool(
		mcp.NewTool("assign_ticket",
			mcp.WithDescription("Assign a ticket to an agent"),
			mcp.WithString("id", mcp.Required(), mcp.Description("Ticket ID to assign")),
			mcp.WithString("agent", mcp.Required(), mcp.Description("Agent name or email to assign to")),
		),
		handleAssignTicket,
	)

	s.AddTool(
		mcp.NewTool("get_ticket_stats",
			mcp.WithDescription("Get support ticket statistics and metrics"),
			mcp.WithString("period", mcp.Description("Time period for stats (today, week, month). Defaults to today")),
			mcp.WithString("agent", mcp.Description("Filter stats by specific agent")),
		),
		handleGetTicketStats,
	)

	// Add resources
	s.AddResource(
		mcp.NewResource(
			"ticket://{ticket_id}",
			"Support Ticket",
			mcp.WithResourceDescription("Complete support ticket with conversation history"),
			mcp.WithMIMEType("application/json"),
		),
		handleTicketResource,
	)

	s.AddResource(
		mcp.NewResource(
			"customer://{customer_id}",
			"Customer Profile",
			mcp.WithResourceDescription("Customer profile with ticket history"),
			mcp.WithMIMEType("application/json"),
		),
		handleCustomerResource,
	)

	// Print capabilities
	fmt.Println("=== Customer Support Service Capabilities ===")
	fmt.Println("Tools:")
	fmt.Println("  - get_ticket: Get detailed information about a support ticket")
	fmt.Println("  - search_tickets: Search support tickets with optional filters")
	fmt.Println("  - reply_to_ticket: Add a reply to a support ticket")
	fmt.Println("  - close_ticket: Close a support ticket")
	fmt.Println("  - update_ticket_priority: Update the priority of a support ticket")
	fmt.Println("  - assign_ticket: Assign a ticket to an agent")
	fmt.Println("  - get_ticket_stats: Get support ticket statistics and metrics")
	fmt.Println("Resources:")
	fmt.Println("  - ticket://{ticket_id}: Support Ticket")
	fmt.Println("  - customer://{customer_id}: Customer Profile")
	fmt.Println("===================================")

	// Start StreamableHTTP server
	log.Println("Starting Customer Support Service on :8086")
	httpServer := server.NewStreamableHTTPServer(s)
	if err := httpServer.Start(":8086"); err != nil {
		log.Fatal(err)
	}
}

func handleGetTicket(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ticketID := req.GetString("id", "")
	if ticketID == "" {
		return nil, fmt.Errorf("ticket id is required")
	}

	ticket, err := getTicketFromRegistry(ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket not found: %s", ticketID)
	}

	// Build messages JSON
	var messagesJSON string
	for i, msg := range ticket.Messages {
		if i > 0 {
			messagesJSON += ","
		}
		messagesJSON += fmt.Sprintf(`{"id":"%s","author":"%s","authorType":"%s","content":"%s","timestamp":"%s","isPublic":%t}`,
			msg.ID, msg.Author, msg.AuthorType, escapeJSON(msg.Content), msg.Timestamp.Format(time.RFC3339), msg.IsPublic)
	}

	// Build tags JSON
	var tagsJSON string
	for i, tag := range ticket.Tags {
		if i > 0 {
			tagsJSON += ","
		}
		tagsJSON += fmt.Sprintf(`"%s"`, tag)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"id":"%s",
		"subject":"%s",
		"status":"%s",
		"priority":"%s",
		"customer":{"id":"%s","name":"%s","email":"%s"},
		"assignedTo":"%s",
		"createdAt":"%s",
		"updatedAt":"%s",
		"tags":[%s],
		"category":"%s",
		"satisfaction":"%s",
		"messages":[%s],
		"messageCount":%d
	}`,
		ticket.ID, ticket.Subject, ticket.Status, ticket.Priority,
		ticket.Customer.ID, ticket.Customer.Name, ticket.Customer.Email,
		ticket.AssignedTo, ticket.CreatedAt.Format(time.RFC3339), ticket.UpdatedAt.Format(time.RFC3339),
		tagsJSON, ticket.Category, ticket.Satisfaction, messagesJSON, len(ticket.Messages))), nil
}

func handleSearchTickets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	status := req.GetString("status", "")
	priority := req.GetString("priority", "")
	assignedTo := req.GetString("assigned_to", "")

	if query == "" {
		return nil, fmt.Errorf("query is required")
	}

	tickets, err := searchTicketsInRegistry(query, status, priority, assignedTo)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Build tickets JSON
	var ticketsJSON string
	for i, t := range tickets {
		if i > 0 {
			ticketsJSON += ","
		}
		ticketsJSON += fmt.Sprintf(`{"id":"%s","subject":"%s","status":"%s","priority":"%s","customer":"%s","assignedTo":"%s","updatedAt":"%s","messageCount":%d}`,
			t.ID, t.Subject, t.Status, t.Priority, t.Customer.Name, t.AssignedTo, t.UpdatedAt.Format(time.RFC3339), len(t.Messages))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"tickets":[%s],
		"total":%d,
		"query":"%s",
		"filters":{"status":"%s","priority":"%s","assignedTo":"%s"}
	}`,
		ticketsJSON, len(tickets), query, status, priority, assignedTo)), nil
}

func handleReplyToTicket(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ticketID := req.GetString("id", "")
	message := req.GetString("message", "")
	isPublicStr := req.GetString("is_public", "true")

	if ticketID == "" || message == "" {
		return nil, fmt.Errorf("ticket id and message are required")
	}

	isPublic := isPublicStr == "true"

	ticket, err := getTicketFromRegistry(ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket not found: %s", ticketID)
	}

	// Add new message
	newMessage := Message{
		ID:         generateMessageID(),
		Author:     "Support Agent",
		AuthorType: "agent",
		Content:    message,
		Timestamp:  time.Now(),
		IsPublic:   isPublic,
	}

	ticket.Messages = append(ticket.Messages, newMessage)
	ticket.UpdatedAt = time.Now()
	ticket.Status = "pending"

	if err := updateTicketInRegistry(ticket); err != nil {
		return nil, fmt.Errorf("failed to update ticket: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"ticketId":"%s",
		"messageId":"%s",
		"message":"Reply added successfully",
		"isPublic":%t,
		"timestamp":"%s",
		"newStatus":"%s"
	}`,
		ticket.ID, newMessage.ID, isPublic, newMessage.Timestamp.Format(time.RFC3339), ticket.Status)), nil
}

func handleCloseTicket(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ticketID := req.GetString("id", "")
	resolution := req.GetString("resolution", "")

	if ticketID == "" {
		return nil, fmt.Errorf("ticket id is required")
	}

	ticket, err := getTicketFromRegistry(ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket not found: %s", ticketID)
	}

	if ticket.Status == "closed" {
		return nil, fmt.Errorf("ticket is already closed")
	}

	oldStatus := ticket.Status
	ticket.Status = "closed"
	ticket.UpdatedAt = time.Now()

	// Add resolution message if provided
	if resolution != "" {
		resolutionMessage := Message{
			ID:         generateMessageID(),
			Author:     "Support Agent",
			AuthorType: "agent",
			Content:    fmt.Sprintf("Ticket closed. Resolution: %s", resolution),
			Timestamp:  time.Now(),
			IsPublic:   true,
		}
		ticket.Messages = append(ticket.Messages, resolutionMessage)
	}

	if err := updateTicketInRegistry(ticket); err != nil {
		return nil, fmt.Errorf("failed to close ticket: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"ticketId":"%s",
		"message":"Ticket closed successfully",
		"previousStatus":"%s",
		"currentStatus":"%s",
		"closedAt":"%s",
		"resolution":"%s"
	}`,
		ticket.ID, oldStatus, ticket.Status, ticket.UpdatedAt.Format(time.RFC3339), resolution)), nil
}

func handleUpdateTicketPriority(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ticketID := req.GetString("id", "")
	priority := req.GetString("priority", "")

	if ticketID == "" || priority == "" {
		return nil, fmt.Errorf("ticket id and priority are required")
	}

	if !isValidPriority(priority) {
		return nil, fmt.Errorf("invalid priority: %s. Must be one of: low, normal, high, urgent", priority)
	}

	ticket, err := getTicketFromRegistry(ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket not found: %s", ticketID)
	}

	oldPriority := ticket.Priority
	ticket.Priority = priority
	ticket.UpdatedAt = time.Now()

	if err := updateTicketInRegistry(ticket); err != nil {
		return nil, fmt.Errorf("failed to update ticket priority: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"ticketId":"%s",
		"message":"Priority updated successfully",
		"previousPriority":"%s",
		"currentPriority":"%s",
		"updatedAt":"%s"
	}`,
		ticket.ID, oldPriority, ticket.Priority, ticket.UpdatedAt.Format(time.RFC3339))), nil
}

func handleAssignTicket(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ticketID := req.GetString("id", "")
	agent := req.GetString("agent", "")

	if ticketID == "" || agent == "" {
		return nil, fmt.Errorf("ticket id and agent are required")
	}

	ticket, err := getTicketFromRegistry(ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket not found: %s", ticketID)
	}

	oldAssignee := ticket.AssignedTo
	ticket.AssignedTo = agent
	ticket.UpdatedAt = time.Now()
	if ticket.Status == "new" {
		ticket.Status = "open"
	}

	if err := updateTicketInRegistry(ticket); err != nil {
		return nil, fmt.Errorf("failed to assign ticket: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"ticketId":"%s",
		"message":"Ticket assigned successfully",
		"previousAssignee":"%s",
		"currentAssignee":"%s",
		"status":"%s",
		"updatedAt":"%s"
	}`,
		ticket.ID, oldAssignee, ticket.AssignedTo, ticket.Status, ticket.UpdatedAt.Format(time.RFC3339))), nil
}

func handleGetTicketStats(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	period := req.GetString("period", "today")
	agent := req.GetString("agent", "")

	stats, err := getTicketStatistics(period, agent)
	if err != nil {
		return nil, fmt.Errorf("failed to get ticket stats: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"period":"%s",
		"agent":"%s",
		"totalTickets":%d,
		"openTickets":%d,
		"closedTickets":%d,
		"averageResponseTime":"%s",
		"averageResolutionTime":"%s",
		"satisfactionRating":%.1f,
		"statusBreakdown":{"new":%d,"open":%d,"pending":%d,"solved":%d,"closed":%d},
		"priorityBreakdown":{"low":%d,"normal":%d,"high":%d,"urgent":%d}
	}`,
		period, agent, stats.TotalTickets, stats.OpenTickets, stats.ClosedTickets,
		stats.AvgResponseTime, stats.AvgResolutionTime, stats.SatisfactionRating,
		stats.StatusBreakdown["new"], stats.StatusBreakdown["open"], stats.StatusBreakdown["pending"],
		stats.StatusBreakdown["solved"], stats.StatusBreakdown["closed"],
		stats.PriorityBreakdown["low"], stats.PriorityBreakdown["normal"],
		stats.PriorityBreakdown["high"], stats.PriorityBreakdown["urgent"])), nil
}

func handleTicketResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	ticketID := extractTicketIDFromURI(req.Params.URI)

	ticket, err := getTicketFromRegistry(ticketID)
	if err != nil {
		return nil, fmt.Errorf("ticket not found: %s", ticketID)
	}

	// Build complete ticket JSON with all details
	var messagesJSON string
	for i, msg := range ticket.Messages {
		if i > 0 {
			messagesJSON += ","
		}
		messagesJSON += fmt.Sprintf(`{"id":"%s","author":"%s","authorType":"%s","content":"%s","timestamp":"%s","isPublic":%t}`,
			msg.ID, msg.Author, msg.AuthorType, escapeJSON(msg.Content), msg.Timestamp.Format(time.RFC3339), msg.IsPublic)
	}

	var tagsJSON string
	for i, tag := range ticket.Tags {
		if i > 0 {
			tagsJSON += ","
		}
		tagsJSON += fmt.Sprintf(`"%s"`, tag)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text: fmt.Sprintf(`{
				"id":"%s",
				"subject":"%s",
				"status":"%s",
				"priority":"%s",
				"customer":{"id":"%s","name":"%s","email":"%s","plan":"%s"},
				"assignedTo":"%s",
				"createdAt":"%s",
				"updatedAt":"%s",
				"tags":[%s],
				"category":"%s",
				"satisfaction":"%s",
				"messages":[%s],
				"metadata":{"source":"%s","channel":"%s","firstResponseTime":"%s"}
			}`,
				ticket.ID, ticket.Subject, ticket.Status, ticket.Priority,
				ticket.Customer.ID, ticket.Customer.Name, ticket.Customer.Email, ticket.Customer.Plan,
				ticket.AssignedTo, ticket.CreatedAt.Format(time.RFC3339), ticket.UpdatedAt.Format(time.RFC3339),
				tagsJSON, ticket.Category, ticket.Satisfaction, messagesJSON,
				ticket.Source, ticket.Channel, ticket.FirstResponseTime),
		},
	}, nil
}

func handleCustomerResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	customerID := extractCustomerIDFromURI(req.Params.URI)

	customer, err := getCustomerFromRegistry(customerID)
	if err != nil {
		return nil, fmt.Errorf("customer not found: %s", customerID)
	}

	// Get customer's ticket history
	tickets := getCustomerTickets(customerID)
	var ticketsJSON string
	for i, t := range tickets {
		if i > 0 {
			ticketsJSON += ","
		}
		ticketsJSON += fmt.Sprintf(`{"id":"%s","subject":"%s","status":"%s","createdAt":"%s"}`,
			t.ID, t.Subject, t.Status, t.CreatedAt.Format(time.RFC3339))
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text: fmt.Sprintf(`{
				"id":"%s",
				"name":"%s",
				"email":"%s",
				"plan":"%s",
				"joinedAt":"%s",
				"totalTickets":%d,
				"satisfactionRating":%.1f,
				"lastActivity":"%s",
				"tickets":[%s]
			}`,
				customer.ID, customer.Name, customer.Email, customer.Plan,
				customer.JoinedAt.Format(time.RFC3339), customer.TotalTickets,
				customer.SatisfactionRating, customer.LastActivity.Format(time.RFC3339), ticketsJSON),
		},
	}, nil
}

// Helper functions and types
type Customer struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Email              string    `json:"email"`
	Plan               string    `json:"plan"`
	JoinedAt           time.Time `json:"joined_at"`
	TotalTickets       int       `json:"total_tickets"`
	SatisfactionRating float64   `json:"satisfaction_rating"`
	LastActivity       time.Time `json:"last_activity"`
}

type Message struct {
	ID         string    `json:"id"`
	Author     string    `json:"author"`
	AuthorType string    `json:"author_type"`
	Content    string    `json:"content"`
	Timestamp  time.Time `json:"timestamp"`
	IsPublic   bool      `json:"is_public"`
}

type Ticket struct {
	ID                  string    `json:"id"`
	Subject             string    `json:"subject"`
	Status              string    `json:"status"`
	Priority            string    `json:"priority"`
	Customer            Customer  `json:"customer"`
	AssignedTo          string    `json:"assigned_to"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	Tags                []string  `json:"tags"`
	Category            string    `json:"category"`
	Satisfaction        string    `json:"satisfaction"`
	Messages            []Message `json:"messages"`
	Source              string    `json:"source"`
	Channel             string    `json:"channel"`
	FirstResponseTime   string    `json:"first_response_time"`
}

type TicketStats struct {
	TotalTickets        int                `json:"total_tickets"`
	OpenTickets         int                `json:"open_tickets"`
	ClosedTickets       int                `json:"closed_tickets"`
	AvgResponseTime     string             `json:"avg_response_time"`
	AvgResolutionTime   string             `json:"avg_resolution_time"`
	SatisfactionRating  float64            `json:"satisfaction_rating"`
	StatusBreakdown     map[string]int     `json:"status_breakdown"`
	PriorityBreakdown   map[string]int     `json:"priority_breakdown"`
}

// Mock data storage
var mockTickets = map[string]*Ticket{
	"ticket_outage": {
		ID:       "ticket_outage",
		Subject:  "URGENT: PDF generation service is down - affecting multiple customers",
		Status:   "open",
		Priority: "urgent",
		Customer: Customer{
			ID:                 "customer_1",
			Name:               "John Smith",
			Email:              "john.smith@acme.com",
			Plan:               "Enterprise",
			JoinedAt:           time.Now().Add(-18 * 30 * 24 * time.Hour),
			TotalTickets:       8,
			SatisfactionRating: 4.2,
			LastActivity:       time.Now().Add(-15 * time.Minute),
		},
		AssignedTo:        "",
		CreatedAt:         time.Now().Add(-30 * time.Minute),
		UpdatedAt:         time.Now().Add(-15 * time.Minute),
		Tags:              []string{"outage", "pdf-generation", "urgent", "enterprise"},
		Category:          "Technical",
		Satisfaction:      "pending",
		Source:            "email",
		Channel:           "support@company.com",
		FirstResponseTime: "pending",
		Messages: []Message{
			{
				ID:         "msg_outage_1",
				Author:     "John Smith",
				AuthorType: "customer",
				Content:    "Our PDF generation feature has been completely down for the past 30 minutes. We're getting 502 errors when trying to generate any documents. This is severely impacting our business operations as we need to send invoices to our clients. Please prioritize this issue immediately. Our customer ID is ACME-CORP and we're on the Enterprise plan.",
				Timestamp:  time.Now().Add(-30 * time.Minute),
				IsPublic:   true,
			},
			{
				ID:         "msg_outage_2",
				Author:     "John Smith",
				AuthorType: "customer",
				Content:    "Update: The issue is still ongoing. We've tried multiple document sizes and types, all are failing with the same 502 gateway error. Our clients are starting to ask questions about delayed invoices. We urgently need this resolved or at least an ETA on the fix.",
				Timestamp:  time.Now().Add(-15 * time.Minute),
				IsPublic:   true,
			},
		},
	},
	"ticket_1": {
		ID:       "ticket_1",
		Subject:  "Unable to log in to account",
		Status:   "open",
		Priority: "high",
		Customer: Customer{
			ID:                 "customer_1",
			Name:               "John Smith",
			Email:              "john.smith@acme.com",
			Plan:               "Premium",
			JoinedAt:           time.Now().Add(-6 * 30 * 24 * time.Hour),
			TotalTickets:       3,
			SatisfactionRating: 4.2,
			LastActivity:       time.Now().Add(-2 * time.Hour),
		},
		AssignedTo:        "Sarah Johnson",
		CreatedAt:         time.Now().Add(-4 * time.Hour),
		UpdatedAt:         time.Now().Add(-30 * time.Minute),
		Tags:              []string{"login", "authentication", "urgent"},
		Category:          "Technical",
		Satisfaction:      "pending",
		Source:            "email",
		Channel:           "support@company.com",
		FirstResponseTime: "45m",
		Messages: []Message{
			{
				ID:         "msg_1",
				Author:     "John Smith",
				AuthorType: "customer",
				Content:    "Hi, I'm unable to log in to my account. I keep getting an 'invalid credentials' error even though I'm sure my password is correct. This is urgent as I need to access my dashboard for a client presentation.",
				Timestamp:  time.Now().Add(-4 * time.Hour),
				IsPublic:   true,
			},
			{
				ID:         "msg_2",
				Author:     "Sarah Johnson",
				AuthorType: "agent",
				Content:    "Hi John, I'm sorry to hear you're having trouble logging in. Let me help you resolve this. Can you please try resetting your password using the 'Forgot Password' link? Also, please clear your browser cache and try again.",
				Timestamp:  time.Now().Add(-3*time.Hour - 15*time.Minute),
				IsPublic:   true,
			},
			{
				ID:         "msg_3",
				Author:     "John Smith",
				AuthorType: "customer",
				Content:    "I tried resetting my password and clearing the cache, but I'm still getting the same error. Is there a server issue?",
				Timestamp:  time.Now().Add(-2*time.Hour - 30*time.Minute),
				IsPublic:   true,
			},
			{
				ID:         "msg_4",
				Author:     "Sarah Johnson",
				AuthorType: "agent",
				Content:    "Checking our server logs now. I can see some authentication service issues around the time you reported. Our engineering team is investigating.",
				Timestamp:  time.Now().Add(-30 * time.Minute),
				IsPublic:   false,
			},
		},
	},
	"ticket_2": {
		ID:       "ticket_2",
		Subject:  "Billing discrepancy on last invoice",
		Status:   "pending",
		Priority: "normal",
		Customer: Customer{
			ID:                 "customer_2",
			Name:               "Emily Chen",
			Email:              "emily.chen@nexus-corp.com",
			Plan:               "Enterprise",
			JoinedAt:           time.Now().Add(-2 * 365 * 24 * time.Hour),
			TotalTickets:       8,
			SatisfactionRating: 4.8,
			LastActivity:       time.Now().Add(-1 * 24 * time.Hour),
		},
		AssignedTo:        "Michael Brown",
		CreatedAt:         time.Now().Add(-2 * 24 * time.Hour),
		UpdatedAt:         time.Now().Add(-6 * time.Hour),
		Tags:              []string{"billing", "invoice", "enterprise"},
		Category:          "Billing",
		Satisfaction:      "good",
		Source:            "web",
		Channel:           "support portal",
		FirstResponseTime: "2h 15m",
		Messages: []Message{
			{
				ID:         "msg_5",
				Author:     "Emily Chen",
				AuthorType: "customer",
				Content:    "Hello, I've noticed a discrepancy on our latest invoice (#INV-2024-0328). We're being charged for 50 user licenses but we only have 42 active users. Could you please review this?",
				Timestamp:  time.Now().Add(-2 * 24 * time.Hour),
				IsPublic:   true,
			},
			{
				ID:         "msg_6",
				Author:     "Michael Brown",
				AuthorType: "agent",
				Content:    "Hi Emily, thank you for bringing this to our attention. I'll review your account and the invoice details. Let me check your current user count and billing history.",
				Timestamp:  time.Now().Add(-1*24*time.Hour - 22*time.Hour),
				IsPublic:   true,
			},
			{
				ID:         "msg_7",
				Author:     "Michael Brown",
				AuthorType: "agent",
				Content:    "I've reviewed your account and confirmed the discrepancy. You're correct - you have 42 active users but were charged for 50. I'm processing a credit for the difference and will send you a corrected invoice.",
				Timestamp:  time.Now().Add(-6 * time.Hour),
				IsPublic:   true,
			},
		},
	},
	"ticket_3": {
		ID:       "ticket_3",
		Subject:  "Feature request: Dark mode support",
		Status:   "open",
		Priority: "low",
		Customer: Customer{
			ID:                 "customer_3",
			Name:               "David Rodriguez",
			Email:              "d.rodriguez@pinnacle.io",
			Plan:               "Professional",
			JoinedAt:           time.Now().Add(-8 * 30 * 24 * time.Hour),
			TotalTickets:       5,
			SatisfactionRating: 4.0,
			LastActivity:       time.Now().Add(-3 * 24 * time.Hour),
		},
		AssignedTo:        "Jessica Williams",
		CreatedAt:         time.Now().Add(-5 * 24 * time.Hour),
		UpdatedAt:         time.Now().Add(-3 * 24 * time.Hour),
		Tags:              []string{"feature-request", "ui", "dark-mode"},
		Category:          "Feature Request",
		Satisfaction:      "pending",
		Source:            "chat",
		Channel:           "website chat",
		FirstResponseTime: "1h 30m",
		Messages: []Message{
			{
				ID:         "msg_8",
				Author:     "David Rodriguez",
				AuthorType: "customer",
				Content:    "Hi there! Our team really loves using your platform, but we'd love to see dark mode support added. Many of us work late hours and would appreciate a darker interface that's easier on the eyes.",
				Timestamp:  time.Now().Add(-5 * 24 * time.Hour),
				IsPublic:   true,
			},
			{
				ID:         "msg_9",
				Author:     "Jessica Williams",
				AuthorType: "agent",
				Content:    "Hi David! Thank you for the feedback. Dark mode is definitely something we've been considering. I'll forward this to our product team for evaluation. We really appreciate customers like you who take the time to share improvement suggestions!",
				Timestamp:  time.Now().Add(-4*24*time.Hour - 22*time.Hour + 30*time.Minute),
				IsPublic:   true,
			},
		},
	},
	"ticket_4": {
		ID:       "ticket_4",
		Subject:  "API rate limit exceeded - need increase",
		Status:   "solved",
		Priority: "urgent",
		Customer: Customer{
			ID:                 "customer_4",
			Name:               "Lisa Thompson",
			Email:              "lisa.t@venture-dynamics.com",
			Plan:               "Enterprise",
			JoinedAt:           time.Now().Add(-18 * 30 * 24 * time.Hour),
			TotalTickets:       12,
			SatisfactionRating: 4.5,
			LastActivity:       time.Now().Add(-1 * 24 * time.Hour),
		},
		AssignedTo:        "Alex Rodriguez",
		CreatedAt:         time.Now().Add(-7 * 24 * time.Hour),
		UpdatedAt:         time.Now().Add(-1 * 24 * time.Hour),
		Tags:              []string{"api", "rate-limit", "enterprise", "urgent"},
		Category:          "Technical",
		Satisfaction:      "excellent",
		Source:            "phone",
		Channel:           "support hotline",
		FirstResponseTime: "15m",
		Messages: []Message{
			{
				ID:         "msg_10",
				Author:     "Lisa Thompson",
				AuthorType: "customer",
				Content:    "We're hitting our API rate limits during peak hours and it's causing issues with our production systems. We need an immediate increase to our rate limits. This is affecting our customers.",
				Timestamp:  time.Now().Add(-7 * 24 * time.Hour),
				IsPublic:   true,
			},
			{
				ID:         "msg_11",
				Author:     "Alex Rodriguez",
				AuthorType: "agent",
				Content:    "Hi Lisa, I understand this is urgent. Let me check your current usage patterns and get this resolved quickly. I'm escalating this to our API team for immediate attention.",
				Timestamp:  time.Now().Add(-7*24*time.Hour + 15*time.Minute),
				IsPublic:   true,
			},
			{
				ID:         "msg_12",
				Author:     "Alex Rodriguez",
				AuthorType: "agent",
				Content:    "Good news! I've increased your rate limits from 1000 to 5000 requests per minute. The changes are live now. Please test and let me know if you need any further adjustments.",
				Timestamp:  time.Now().Add(-6*24*time.Hour - 30*time.Minute),
				IsPublic:   true,
			},
			{
				ID:         "msg_13",
				Author:     "Lisa Thompson",
				AuthorType: "customer",
				Content:    "Perfect! The rate limit increase resolved our issues. Thank you for the quick response and resolution. Excellent support as always!",
				Timestamp:  time.Now().Add(-1 * 24 * time.Hour),
				IsPublic:   true,
			},
		},
	},
	"ticket_5": {
		ID:       "ticket_5",
		Subject:  "Data export functionality not working",
		Status:   "new",
		Priority: "normal",
		Customer: Customer{
			ID:                 "customer_5",
			Name:               "Marcus Wright",
			Email:              "marcus@synergy-solutions.net",
			Plan:               "Professional",
			JoinedAt:           time.Now().Add(-4 * 30 * 24 * time.Hour),
			TotalTickets:       2,
			SatisfactionRating: 3.8,
			LastActivity:       time.Now().Add(-30 * time.Minute),
		},
		AssignedTo:        "",
		CreatedAt:         time.Now().Add(-30 * time.Minute),
		UpdatedAt:         time.Now().Add(-30 * time.Minute),
		Tags:              []string{"export", "data", "bug"},
		Category:          "Technical",
		Satisfaction:      "pending",
		Source:            "email",
		Channel:           "support@company.com",
		FirstResponseTime: "pending",
		Messages: []Message{
			{
				ID:         "msg_14",
				Author:     "Marcus Wright",
				AuthorType: "customer",
				Content:    "Hi, I'm trying to export my data using the export feature in the dashboard, but when I click the 'Export' button, nothing happens. I've tried different browsers and the issue persists. Could you please help?",
				Timestamp:  time.Now().Add(-30 * time.Minute),
				IsPublic:   true,
			},
		},
	},
}

var mockCustomers = map[string]*Customer{
	"customer_1": {
		ID:                 "customer_1",
		Name:               "John Smith",
		Email:              "john.smith@acme.com",
		Plan:               "Premium",
		JoinedAt:           time.Now().Add(-6 * 30 * 24 * time.Hour),
		TotalTickets:       3,
		SatisfactionRating: 4.2,
		LastActivity:       time.Now().Add(-2 * time.Hour),
	},
	"customer_2": {
		ID:                 "customer_2",
		Name:               "Emily Chen",
		Email:              "emily.chen@nexus-corp.com",
		Plan:               "Enterprise",
		JoinedAt:           time.Now().Add(-2 * 365 * 24 * time.Hour),
		TotalTickets:       8,
		SatisfactionRating: 4.8,
		LastActivity:       time.Now().Add(-1 * 24 * time.Hour),
	},
	"customer_3": {
		ID:                 "customer_3",
		Name:               "David Rodriguez",
		Email:              "d.rodriguez@pinnacle.io",
		Plan:               "Professional",
		JoinedAt:           time.Now().Add(-8 * 30 * 24 * time.Hour),
		TotalTickets:       5,
		SatisfactionRating: 4.0,
		LastActivity:       time.Now().Add(-3 * 24 * time.Hour),
	},
	"customer_4": {
		ID:                 "customer_4",
		Name:               "Lisa Thompson",
		Email:              "lisa.t@venture-dynamics.com",
		Plan:               "Enterprise",
		JoinedAt:           time.Now().Add(-18 * 30 * 24 * time.Hour),
		TotalTickets:       12,
		SatisfactionRating: 4.5,
		LastActivity:       time.Now().Add(-1 * 24 * time.Hour),
	},
	"customer_5": {
		ID:                 "customer_5",
		Name:               "Marcus Wright",
		Email:              "marcus@synergy-solutions.net",
		Plan:               "Professional",
		JoinedAt:           time.Now().Add(-4 * 30 * 24 * time.Hour),
		TotalTickets:       2,
		SatisfactionRating: 3.8,
		LastActivity:       time.Now().Add(-30 * time.Minute),
	},
}

func getTicketFromRegistry(ticketID string) (*Ticket, error) {
	if ticket, exists := mockTickets[ticketID]; exists {
		return ticket, nil
	}
	return nil, fmt.Errorf("ticket not found")
}

func getCustomerFromRegistry(customerID string) (*Customer, error) {
	if customer, exists := mockCustomers[customerID]; exists {
		return customer, nil
	}
	return nil, fmt.Errorf("customer not found")
}

func updateTicketInRegistry(ticket *Ticket) error {
	mockTickets[ticket.ID] = ticket
	return nil
}

func searchTicketsInRegistry(query, status, priority, assignedTo string) ([]*Ticket, error) {
	var results []*Ticket
	queryLower := strings.ToLower(query)

	for _, ticket := range mockTickets {
		// Check if ticket matches search criteria
		matches := false
		
		// Search in subject, customer name, and message content
		if strings.Contains(strings.ToLower(ticket.Subject), queryLower) ||
			strings.Contains(strings.ToLower(ticket.Customer.Name), queryLower) ||
			strings.Contains(strings.ToLower(ticket.Customer.Email), queryLower) {
			matches = true
		}
		
		// Search in message content
		for _, msg := range ticket.Messages {
			if strings.Contains(strings.ToLower(msg.Content), queryLower) {
				matches = true
				break
			}
		}

		if !matches {
			continue
		}

		// Apply filters
		if status != "" && ticket.Status != status {
			continue
		}
		if priority != "" && ticket.Priority != priority {
			continue
		}
		if assignedTo != "" && ticket.AssignedTo != assignedTo {
			continue
		}

		results = append(results, ticket)
	}

	return results, nil
}

func getCustomerTickets(customerID string) []*Ticket {
	var tickets []*Ticket
	for _, ticket := range mockTickets {
		if ticket.Customer.ID == customerID {
			tickets = append(tickets, ticket)
		}
	}
	return tickets
}

func getTicketStatistics(period, agent string) (*TicketStats, error) {
	stats := &TicketStats{
		StatusBreakdown:   make(map[string]int),
		PriorityBreakdown: make(map[string]int),
	}

	var filteredTickets []*Ticket
	for _, ticket := range mockTickets {
		// Apply agent filter
		if agent != "" && ticket.AssignedTo != agent {
			continue
		}
		
		// Apply period filter (simplified for mock)
		switch period {
		case "today":
			if ticket.UpdatedAt.Before(time.Now().Add(-24 * time.Hour)) {
				continue
			}
		case "week":
			if ticket.UpdatedAt.Before(time.Now().Add(-7 * 24 * time.Hour)) {
				continue
			}
		case "month":
			if ticket.UpdatedAt.Before(time.Now().Add(-30 * 24 * time.Hour)) {
				continue
			}
		}
		
		filteredTickets = append(filteredTickets, ticket)
	}

	stats.TotalTickets = len(filteredTickets)
	
	for _, ticket := range filteredTickets {
		// Count by status
		stats.StatusBreakdown[ticket.Status]++
		if ticket.Status == "open" || ticket.Status == "new" || ticket.Status == "pending" {
			stats.OpenTickets++
		} else if ticket.Status == "closed" || ticket.Status == "solved" {
			stats.ClosedTickets++
		}
		
		// Count by priority
		stats.PriorityBreakdown[ticket.Priority]++
	}

	// Mock averages
	stats.AvgResponseTime = "2h 15m"
	stats.AvgResolutionTime = "1d 4h"
	stats.SatisfactionRating = 4.3

	return stats, nil
}

func isValidPriority(priority string) bool {
	return priority == "low" || priority == "normal" || priority == "high" || priority == "urgent"
}

func generateMessageID() string {
	return fmt.Sprintf("msg_%d", time.Now().UnixNano())
}

func extractTicketIDFromURI(uri string) string {
	if len(uri) > 9 && uri[:9] == "ticket://" {
		return uri[9:]
	}
	return uri
}

func extractCustomerIDFromURI(uri string) string {
	if len(uri) > 11 && uri[:11] == "customer://" {
		return uri[11:]
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