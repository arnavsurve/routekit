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
	s := server.NewMCPServer("CRM & SalesOps Service", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	)

	// Add CRM tools
	s.AddTool(
		mcp.NewTool("search_contacts",
			mcp.WithDescription("Search contacts with optional pipeline stage filter"),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search query for contact name, email, or company")),
			mcp.WithString("stage", mcp.Description("Filter by pipeline stage")),
		),
		handleSearchContacts,
	)

	s.AddTool(
		mcp.NewTool("update_pipeline_stage",
			mcp.WithDescription("Update a contact's pipeline stage"),
			mcp.WithString("contact_id", mcp.Required()),
			mcp.WithString("stage", mcp.Required()),
		),
		handleUpdatePipelineStage,
	)

	s.AddTool(
		mcp.NewTool("create_lead",
			mcp.WithDescription("Create a new lead in the CRM"),
			mcp.WithString("name", mcp.Required()),
			mcp.WithString("email", mcp.Required()),
			mcp.WithString("company", mcp.Required()),
		),
		handleCreateLead,
	)

	s.AddTool(
		mcp.NewTool("get_contact_summary",
			mcp.WithDescription("Get detailed summary of a contact"),
			mcp.WithString("contact_id", mcp.Required()),
		),
		handleGetContactSummary,
	)

	s.AddTool(
		mcp.NewTool("get_customer_account",
			mcp.WithDescription("Get customer account details by email or contact ID"),
			mcp.WithString("email", mcp.Description("Customer email address")),
			mcp.WithString("contact_id", mcp.Description("Contact ID")),
		),
		handleGetCustomerAccount,
	)

	s.AddTool(
		mcp.NewTool("get_account_details",
			mcp.WithDescription("Get detailed account information including plan, revenue, and billing"),
			mcp.WithString("account_id", mcp.Required(), mcp.Description("Account ID to retrieve details for")),
		),
		handleGetAccountDetails,
	)

	// Add resources
	s.AddResource(
		mcp.NewResource(
			"contacts://{contact_id}",
			"Contact Profile",
			mcp.WithResourceDescription("Contact profile and interaction history"),
			mcp.WithMIMEType("application/json"),
		),
		handleContactResource,
	)

	// Print capabilities
	fmt.Println("=== CRM & SalesOps Service Capabilities ===")
	fmt.Println("Tools:")
	fmt.Println("  - search_contacts: Search contacts with optional pipeline stage filter")
	fmt.Println("  - update_pipeline_stage: Update a contact's pipeline stage")
	fmt.Println("  - create_lead: Create a new lead in the CRM")
	fmt.Println("  - get_contact_summary: Get detailed summary of a contact")
	fmt.Println("  - get_customer_account: Get customer account details by email or contact ID")
	fmt.Println("  - get_account_details: Get detailed account information including plan, revenue, and billing")
	fmt.Println("Resources:")
	fmt.Println("  - contacts://{contact_id}: Contact Profile")
	fmt.Println("===================================")

	// Start StreamableHTTP server
	log.Println("Starting CRM & SalesOps Service on :8083")
	httpServer := server.NewStreamableHTTPServer(s)
	if err := httpServer.Start(":8083"); err != nil {
		log.Fatal(err)
	}
}

func handleSearchContacts(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	stage := req.GetString("stage", "")

	// Allow empty queries to return all contacts
	// Also treat "*" as a special case to return all contacts

	// Search contacts with optional stage filter
	contacts, err := searchContactsInCRM(query, stage)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Build JSON response
	var contactsJSON string
	for i, c := range contacts {
		if i > 0 {
			contactsJSON += ","
		}
		contactsJSON += fmt.Sprintf(`{"id":"%s","name":"%s","email":"%s","company":"%s","stage":"%s","lastActivity":"%s"}`,
			c.ID, c.Name, c.Email, c.Company, c.Stage, c.LastActivity.Format(time.RFC3339))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"contacts":[%s],"total":%d,"query":"%s","stage":"%s"}`,
		contactsJSON, len(contacts), query, stage)), nil
}

func handleUpdatePipelineStage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	contactID := req.GetString("contact_id", "")
	stage := req.GetString("stage", "")

	if contactID == "" || stage == "" {
		return nil, fmt.Errorf("contact_id and stage are required")
	}

	// Get contact
	contact, err := getContactFromCRM(contactID)
	if err != nil {
		return nil, fmt.Errorf("contact not found: %s", contactID)
	}

	// Update stage
	oldStage := contact.Stage
	contact.Stage = stage
	contact.LastUpdated = time.Now()
	
	if err := saveContactToCRM(contact); err != nil {
		return nil, fmt.Errorf("failed to update contact: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"id":"%s","name":"%s","previous_stage":"%s","current_stage":"%s","message":"Pipeline stage updated successfully"}`,
		contact.ID, contact.Name, oldStage, contact.Stage)), nil
}

func handleCreateLead(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.GetString("name", "")
	email := req.GetString("email", "")
	company := req.GetString("company", "")

	if name == "" || email == "" || company == "" {
		return nil, fmt.Errorf("name, email, and company are required")
	}

	// Validate input
	if !isValidEmail(email) {
		return nil, fmt.Errorf("invalid email format: %s", email)
	}

	// Create contact
	contact := &Contact{
		ID:           generateID(),
		Name:         name,
		Email:        email,
		Company:      company,
		Stage:        "New Lead",
		CreatedAt:    time.Now(),
		LastUpdated:  time.Now(),
		LastActivity: time.Now(),
		Notes:        []Note{{Content: "Lead created", Timestamp: time.Now()}},
	}

	if err := saveContactToCRM(contact); err != nil {
		return nil, fmt.Errorf("failed to create lead: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"id":"%s","message":"Lead created successfully","contact":{"id":"%s","name":"%s","email":"%s","company":"%s","stage":"%s"}}`,
		contact.ID, contact.ID, contact.Name, contact.Email, contact.Company, contact.Stage)), nil
}

func handleGetContactSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	contactID := req.GetString("contact_id", "")
	if contactID == "" {
		return nil, fmt.Errorf("contact_id is required")
	}

	// Get contact
	contact, err := getContactFromCRM(contactID)
	if err != nil {
		return nil, fmt.Errorf("contact not found: %s", contactID)
	}

	// Build notes JSON
	var notesJSON string
	for i, note := range contact.Notes {
		if i > 0 {
			notesJSON += ","
		}
		notesJSON += fmt.Sprintf(`{"content":"%s","timestamp":"%s"}`,
			note.Content, note.Timestamp.Format(time.RFC3339))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"id":"%s",
		"name":"%s",
		"email":"%s",
		"company":"%s",
		"stage":"%s",
		"created_at":"%s",
		"last_updated":"%s",
		"last_activity":"%s",
		"notes":[%s]
	}`,
		contact.ID, contact.Name, contact.Email, contact.Company, contact.Stage,
		contact.CreatedAt.Format(time.RFC3339), contact.LastUpdated.Format(time.RFC3339),
		contact.LastActivity.Format(time.RFC3339), notesJSON)), nil
}

func handleGetCustomerAccount(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	email := req.GetString("email", "")
	contactID := req.GetString("contact_id", "")

	if email == "" && contactID == "" {
		return nil, fmt.Errorf("either email or contact_id is required")
	}

	// Find customer account
	account, err := getCustomerAccountFromCRM(email, contactID)
	if err != nil {
		return nil, fmt.Errorf("customer account not found: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"accountId":"%s",
		"contactId":"%s",
		"companyName":"%s",
		"contactName":"%s",
		"email":"%s",
		"plan":"%s",
		"monthlyRevenue":%d,
		"annualRevenue":%d,
		"status":"%s",
		"tier":"%s",
		"contractStart":"%s",
		"contractEnd":"%s",
		"billingStatus":"%s"
	}`,
		account.AccountID, account.ContactID, account.CompanyName, account.ContactName,
		account.Email, account.Plan, account.MonthlyRevenue, account.AnnualRevenue,
		account.Status, account.Tier, account.ContractStart.Format(time.RFC3339),
		account.ContractEnd.Format(time.RFC3339), account.BillingStatus)), nil
}

func handleGetAccountDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	accountID := req.GetString("account_id", "")
	if accountID == "" {
		return nil, fmt.Errorf("account_id is required")
	}

	// Get detailed account information
	account, err := getAccountDetailsFromCRM(accountID)
	if err != nil {
		return nil, fmt.Errorf("account not found: %s", accountID)
	}

	// Build usage metrics JSON
	var usageJSON string
	for i, usage := range account.UsageMetrics {
		if i > 0 {
			usageJSON += ","
		}
		usageJSON += fmt.Sprintf(`{"metric":"%s","value":%d,"limit":%d,"period":"%s"}`,
			usage.Metric, usage.Value, usage.Limit, usage.Period)
	}

	// Build support metrics JSON
	supportMetrics := account.SupportMetrics
	supportJSON := fmt.Sprintf(`{"totalTickets":%d,"openTickets":%d,"avgResponseTime":"%s","satisfactionScore":%.1f}`,
		supportMetrics.TotalTickets, supportMetrics.OpenTickets, supportMetrics.AvgResponseTime, supportMetrics.SatisfactionScore)

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"accountId":"%s",
		"companyName":"%s",
		"plan":"%s",
		"monthlyRevenue":%d,
		"annualRevenue":%d,
		"status":"%s",
		"tier":"%s",
		"billingStatus":"%s",
		"contractStart":"%s",
		"contractEnd":"%s",
		"usageMetrics":[%s],
		"supportMetrics":%s,
		"lastLoginDate":"%s",
		"seats":{"used":%d,"total":%d},
		"features":["%s"]
	}`,
		account.AccountID, account.CompanyName, account.Plan, account.MonthlyRevenue,
		account.AnnualRevenue, account.Status, account.Tier, account.BillingStatus,
		account.ContractStart.Format(time.RFC3339), account.ContractEnd.Format(time.RFC3339),
		usageJSON, supportJSON, account.LastLoginDate.Format(time.RFC3339),
		account.SeatsUsed, account.SeatsTotal, strings.Join(account.Features, `","`+
		""))), nil
}

func handleContactResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	contactID := extractContactIDFromURI(req.Params.URI)

	contact, err := getContactFromCRM(contactID)
	if err != nil {
		return nil, fmt.Errorf("contact not found: %s", contactID)
	}

	// Build notes JSON
	var notesJSON string
	for i, note := range contact.Notes {
		if i > 0 {
			notesJSON += ","
		}
		notesJSON += fmt.Sprintf(`{"content":"%s","timestamp":"%s"}`,
			note.Content, note.Timestamp.Format(time.RFC3339))
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text: fmt.Sprintf(`{
				"id":"%s",
				"name":"%s",
				"email":"%s",
				"company":"%s",
				"stage":"%s",
				"created_at":"%s",
				"last_updated":"%s",
				"last_activity":"%s",
				"notes":[%s]
			}`,
				contact.ID, contact.Name, contact.Email, contact.Company, contact.Stage,
				contact.CreatedAt.Format(time.RFC3339), contact.LastUpdated.Format(time.RFC3339),
				contact.LastActivity.Format(time.RFC3339), notesJSON),
		},
	}, nil
}

// Helper functions and types
type Note struct {
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

type Contact struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	Company      string    `json:"company"`
	Stage        string    `json:"stage"`
	CreatedAt    time.Time `json:"created_at"`
	LastUpdated  time.Time `json:"last_updated"`
	LastActivity time.Time `json:"last_activity"`
	Notes        []Note    `json:"notes"`
}

type CustomerAccount struct {
	AccountID       string    `json:"account_id"`
	ContactID       string    `json:"contact_id"`
	CompanyName     string    `json:"company_name"`
	ContactName     string    `json:"contact_name"`
	Email           string    `json:"email"`
	Plan            string    `json:"plan"`
	MonthlyRevenue  int       `json:"monthly_revenue"`
	AnnualRevenue   int       `json:"annual_revenue"`
	Status          string    `json:"status"`
	Tier            string    `json:"tier"`
	ContractStart   time.Time `json:"contract_start"`
	ContractEnd     time.Time `json:"contract_end"`
	BillingStatus   string    `json:"billing_status"`
}

type UsageMetric struct {
	Metric string `json:"metric"`
	Value  int    `json:"value"`
	Limit  int    `json:"limit"`
	Period string `json:"period"`
}

type SupportMetrics struct {
	TotalTickets      int     `json:"total_tickets"`
	OpenTickets       int     `json:"open_tickets"`
	AvgResponseTime   string  `json:"avg_response_time"`
	SatisfactionScore float64 `json:"satisfaction_score"`
}

type AccountDetails struct {
	AccountID       string           `json:"account_id"`
	CompanyName     string           `json:"company_name"`
	Plan            string           `json:"plan"`
	MonthlyRevenue  int              `json:"monthly_revenue"`
	AnnualRevenue   int              `json:"annual_revenue"`
	Status          string           `json:"status"`
	Tier            string           `json:"tier"`
	BillingStatus   string           `json:"billing_status"`
	ContractStart   time.Time        `json:"contract_start"`
	ContractEnd     time.Time        `json:"contract_end"`
	UsageMetrics    []UsageMetric    `json:"usage_metrics"`
	SupportMetrics  SupportMetrics   `json:"support_metrics"`
	LastLoginDate   time.Time        `json:"last_login_date"`
	SeatsUsed       int              `json:"seats_used"`
	SeatsTotal      int              `json:"seats_total"`
	Features        []string         `json:"features"`
}

func getContactFromCRM(contactID string) (*Contact, error) {
	// Placeholder implementation
	// In a real implementation, this would query a CRM system
	
	// Return different mock contacts based on ID
	switch contactID {
	case "contact_1":
		return &Contact{
			ID:           contactID,
			Name:         "John Smith",
			Email:        "john.smith@acme.com",
			Company:      "ACME Corporation",
			Stage:        "Discovery",
			CreatedAt:    time.Now().Add(-30 * 24 * time.Hour),
			LastUpdated:  time.Now().Add(-2 * 24 * time.Hour),
			LastActivity: time.Now().Add(-2 * 24 * time.Hour),
			Notes: []Note{
				{Content: "Initial contact made", Timestamp: time.Now().Add(-30 * 24 * time.Hour)},
				{Content: "Discussed product needs", Timestamp: time.Now().Add(-15 * 24 * time.Hour)},
				{Content: "Sent proposal", Timestamp: time.Now().Add(-2 * 24 * time.Hour)},
			},
		}, nil
	case "contact_2":
		return &Contact{
			ID:           contactID,
			Name:         "Jane Doe",
			Email:        "jane.doe@example.com",
			Company:      "Example Inc",
			Stage:        "Negotiation",
			CreatedAt:    time.Now().Add(-60 * 24 * time.Hour),
			LastUpdated:  time.Now().Add(-1 * 24 * time.Hour),
			LastActivity: time.Now().Add(-1 * 24 * time.Hour),
			Notes: []Note{
				{Content: "Initial contact made", Timestamp: time.Now().Add(-60 * 24 * time.Hour)},
				{Content: "Demo completed", Timestamp: time.Now().Add(-45 * 24 * time.Hour)},
				{Content: "Technical review passed", Timestamp: time.Now().Add(-30 * 24 * time.Hour)},
				{Content: "Negotiating contract terms", Timestamp: time.Now().Add(-1 * 24 * time.Hour)},
			},
		}, nil
	case "contact_3":
		return &Contact{
			ID:           contactID,
			Name:         "Robert Johnson",
			Email:        "robert@techinnovate.com",
			Company:      "Tech Innovate",
			Stage:        "Closed Won",
			CreatedAt:    time.Now().Add(-90 * 24 * time.Hour),
			LastUpdated:  time.Now().Add(-5 * 24 * time.Hour),
			LastActivity: time.Now().Add(-5 * 24 * time.Hour),
			Notes: []Note{
				{Content: "Initial contact made", Timestamp: time.Now().Add(-90 * 24 * time.Hour)},
				{Content: "Multiple demos completed", Timestamp: time.Now().Add(-75 * 24 * time.Hour)},
				{Content: "Contract signed", Timestamp: time.Now().Add(-5 * 24 * time.Hour)},
			},
		}, nil
	default:
		// For any other ID, generate a contact based on the ID
		return &Contact{
			ID:           contactID,
			Name:         "Generated Contact",
			Email:        fmt.Sprintf("contact%s@example.com", contactID),
			Company:      "Generated Company",
			Stage:        "New Lead",
			CreatedAt:    time.Now().Add(-10 * 24 * time.Hour),
			LastUpdated:  time.Now().Add(-1 * 24 * time.Hour),
			LastActivity: time.Now().Add(-1 * 24 * time.Hour),
			Notes: []Note{
				{Content: "Auto-generated contact", Timestamp: time.Now().Add(-10 * 24 * time.Hour)},
			},
		}, nil
	}
}

func isValidEmail(email string) bool {
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func generateID() string {
	// Placeholder implementation
	return fmt.Sprintf("contact_%d", time.Now().UnixNano())
}

func saveContactToCRM(contact *Contact) error {
	// Placeholder implementation
	// In a real implementation, this would save to a CRM system
	return nil
}

func searchContactsInCRM(query string, stage string) ([]*Contact, error) {
	// Placeholder implementation
	// In a real implementation, this would search a CRM system
	contacts := []*Contact{
		{
			ID:           "contact_1",
			Name:         "John Smith",
			Email:        "john.smith@acme.com",
			Company:      "ACME Corporation",
			Stage:        "Discovery",
			LastActivity: time.Now().Add(-2 * 24 * time.Hour),
		},
		{
			ID:           "contact_2",
			Name:         "Jane Doe",
			Email:        "jane.doe@example.com",
			Company:      "Example Inc",
			Stage:        "Negotiation",
			LastActivity: time.Now().Add(-1 * 24 * time.Hour),
		},
		{
			ID:           "contact_3",
			Name:         "Robert Johnson",
			Email:        "robert@techinnovate.com",
			Company:      "Tech Innovate",
			Stage:        "Closed Won",
			LastActivity: time.Now().Add(-5 * 24 * time.Hour),
		},
		{
			ID:           "contact_4",
			Name:         "Sarah Williams",
			Email:        "sarah@globex.com",
			Company:      "Globex Corporation",
			Stage:        "Discovery",
			LastActivity: time.Now().Add(-3 * 24 * time.Hour),
		},
		{
			ID:           "contact_5",
			Name:         "Michael Brown",
			Email:        "michael@initech.com",
			Company:      "Initech",
			Stage:        "Proposal",
			LastActivity: time.Now().Add(-7 * 24 * time.Hour),
		},
		{
			ID:           "contact_6",
			Name:         "Emily Chen",
			Email:        "emily.chen@nexus-corp.com",
			Company:      "Nexus Corporation",
			Stage:        "Qualified Lead",
			LastActivity: time.Now().Add(-4 * 24 * time.Hour),
		},
		{
			ID:           "contact_7",
			Name:         "David Rodriguez",
			Email:        "d.rodriguez@pinnacle.io",
			Company:      "Pinnacle Solutions",
			Stage:        "Demo Scheduled",
			LastActivity: time.Now().Add(-6 * 24 * time.Hour),
		},
		{
			ID:           "contact_8",
			Name:         "Lisa Thompson",
			Email:        "lisa.t@venture-dynamics.com",
			Company:      "Venture Dynamics",
			Stage:        "Closed Lost",
			LastActivity: time.Now().Add(-14 * 24 * time.Hour),
		},
		{
			ID:           "contact_9",
			Name:         "Marcus Wright",
			Email:        "marcus@synergy-solutions.net",
			Company:      "Synergy Solutions",
			Stage:        "Contract Review",
			LastActivity: time.Now().Add(-8 * time.Hour),
		},
		{
			ID:           "contact_10",
			Name:         "Amanda Foster",
			Email:        "amanda.foster@digital-edge.com",
			Company:      "Digital Edge Technologies",
			Stage:        "Negotiation",
			LastActivity: time.Now().Add(-12 * time.Hour),
		},
		{
			ID:           "contact_11",
			Name:         "Kevin Park",
			Email:        "kevin.park@future-systems.org",
			Company:      "Future Systems Inc",
			Stage:        "Discovery",
			LastActivity: time.Now().Add(-9 * 24 * time.Hour),
		},
		{
			ID:           "contact_12",
			Name:         "Rachel Green",
			Email:        "rachel@quantum-labs.co",
			Company:      "Quantum Labs",
			Stage:        "Proposal",
			LastActivity: time.Now().Add(-5 * 24 * time.Hour),
		},
	}
	
	// Filter by query (case-insensitive)
	queryLower := strings.ToLower(query)
	filtered := []*Contact{}
	for _, c := range contacts {
		// If query is empty or "*", include all contacts
		if query == "" || query == "*" || 
		   strings.Contains(strings.ToLower(c.Name), queryLower) ||
		   strings.Contains(strings.ToLower(c.Email), queryLower) ||
		   strings.Contains(strings.ToLower(c.Company), queryLower) {
			// If stage filter is provided, apply it
			if stage == "" || c.Stage == stage {
				filtered = append(filtered, c)
			}
		}
	}
	
	return filtered, nil
}

func extractContactIDFromURI(uri string) string {
	// Extract contact ID from URI like "contacts://123"
	if len(uri) > 11 && uri[:11] == "contacts://" {
		return uri[11:]
	}
	return uri
}

// Mock customer account data for demo scenario
var mockCustomerAccounts = map[string]*CustomerAccount{
	"acme-corp": {
		AccountID:       "acme-corp",
		ContactID:       "contact_1",
		CompanyName:     "ACME Corporation",
		ContactName:     "John Smith",
		Email:           "john.smith@acme.com",
		Plan:            "Enterprise",
		MonthlyRevenue:  18000,
		AnnualRevenue:   216000,
		Status:          "active",
		Tier:            "platinum",
		ContractStart:   time.Now().Add(-18 * 30 * 24 * time.Hour),
		ContractEnd:     time.Now().Add(6 * 30 * 24 * time.Hour),
		BillingStatus:   "current",
	},
	"nexus-corp": {
		AccountID:       "nexus-corp",
		ContactID:       "contact_6",
		CompanyName:     "Nexus Corporation",
		ContactName:     "Emily Chen",
		Email:           "emily.chen@nexus-corp.com",
		Plan:            "Professional",
		MonthlyRevenue:  2500,
		AnnualRevenue:   30000,
		Status:          "active",
		Tier:            "gold",
		ContractStart:   time.Now().Add(-8 * 30 * 24 * time.Hour),
		ContractEnd:     time.Now().Add(4 * 30 * 24 * time.Hour),
		BillingStatus:   "current",
	},
	"pinnacle-solutions": {
		AccountID:       "pinnacle-solutions",
		ContactID:       "contact_7",
		CompanyName:     "Pinnacle Solutions",
		ContactName:     "David Rodriguez",
		Email:           "d.rodriguez@pinnacle.io",
		Plan:            "Professional",
		MonthlyRevenue:  3200,
		AnnualRevenue:   38400,
		Status:          "active",
		Tier:            "gold",
		ContractStart:   time.Now().Add(-12 * 30 * 24 * time.Hour),
		ContractEnd:     time.Now().Add(0 * 30 * 24 * time.Hour),
		BillingStatus:   "current",
	},
}

var mockAccountDetails = map[string]*AccountDetails{
	"acme-corp": {
		AccountID:       "acme-corp",
		CompanyName:     "ACME Corporation",
		Plan:            "Enterprise",
		MonthlyRevenue:  18000,
		AnnualRevenue:   216000,
		Status:          "active",
		Tier:            "platinum",
		BillingStatus:   "current",
		ContractStart:   time.Now().Add(-18 * 30 * 24 * time.Hour),
		ContractEnd:     time.Now().Add(6 * 30 * 24 * time.Hour),
		UsageMetrics: []UsageMetric{
			{Metric: "api_calls", Value: 450000, Limit: 500000, Period: "monthly"},
			{Metric: "storage_gb", Value: 850, Limit: 1000, Period: "monthly"},
			{Metric: "users", Value: 42, Limit: 50, Period: "monthly"},
		},
		SupportMetrics: SupportMetrics{
			TotalTickets:      8,
			OpenTickets:       1,
			AvgResponseTime:   "45m",
			SatisfactionScore: 4.2,
		},
		LastLoginDate: time.Now().Add(-2 * time.Hour),
		SeatsUsed:     42,
		SeatsTotal:    50,
		Features:      []string{"api_access", "premium_support", "custom_integrations", "sso", "audit_logs"},
	},
	"nexus-corp": {
		AccountID:       "nexus-corp",
		CompanyName:     "Nexus Corporation",
		Plan:            "Professional",
		MonthlyRevenue:  2500,
		AnnualRevenue:   30000,
		Status:          "active",
		Tier:            "gold",
		BillingStatus:   "current",
		ContractStart:   time.Now().Add(-8 * 30 * 24 * time.Hour),
		ContractEnd:     time.Now().Add(4 * 30 * 24 * time.Hour),
		UsageMetrics: []UsageMetric{
			{Metric: "api_calls", Value: 75000, Limit: 100000, Period: "monthly"},
			{Metric: "storage_gb", Value: 180, Limit: 250, Period: "monthly"},
			{Metric: "users", Value: 12, Limit: 15, Period: "monthly"},
		},
		SupportMetrics: SupportMetrics{
			TotalTickets:      3,
			OpenTickets:       0,
			AvgResponseTime:   "2h 15m",
			SatisfactionScore: 4.8,
		},
		LastLoginDate: time.Now().Add(-4 * time.Hour),
		SeatsUsed:     12,
		SeatsTotal:    15,
		Features:      []string{"api_access", "standard_support", "basic_integrations"},
	},
}

func getCustomerAccountFromCRM(email, contactID string) (*CustomerAccount, error) {
	// Search by email first
	if email != "" {
		for _, account := range mockCustomerAccounts {
			if account.Email == email {
				return account, nil
			}
		}
	}
	
	// Search by contact ID
	if contactID != "" {
		for _, account := range mockCustomerAccounts {
			if account.ContactID == contactID {
				return account, nil
			}
		}
	}
	
	return nil, fmt.Errorf("customer account not found")
}

func getAccountDetailsFromCRM(accountID string) (*AccountDetails, error) {
	if account, exists := mockAccountDetails[accountID]; exists {
		return account, nil
	}
	return nil, fmt.Errorf("account details not found")
}
