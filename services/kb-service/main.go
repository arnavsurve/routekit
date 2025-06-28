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
	s := server.NewMCPServer("Internal Knowledge Base Service", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	)

	// Add Knowledge Base tools
	s.AddTool(
		mcp.NewTool("search_docs",
			mcp.WithDescription("Search internal documentation"),
			mcp.WithString("query", mcp.Required(), mcp.Description("Search query for document title or content")),
		),
		handleSearchDocs,
	)

	s.AddTool(
		mcp.NewTool("get_doc_summary",
			mcp.WithDescription("Get a summary of a document"),
			mcp.WithString("doc_id", mcp.Required()),
		),
		handleGetDocSummary,
	)

	s.AddTool(
		mcp.NewTool("create_page",
			mcp.WithDescription("Create a new page in the knowledge base"),
			mcp.WithString("title", mcp.Required()),
			mcp.WithString("body", mcp.Required()),
		),
		handleCreatePage,
	)

	s.AddTool(
		mcp.NewTool("list_recent_updates",
			mcp.WithDescription("List recently updated documents for a team"),
			mcp.WithString("team", mcp.Required()),
		),
		handleListRecentUpdates,
	)

	// Add resources
	s.AddResource(
		mcp.NewResource(
			"docs://{doc_id}",
			"Document",
			mcp.WithResourceDescription("Knowledge base document content"),
			mcp.WithMIMEType("application/json"),
		),
		handleDocResource,
	)

	// Print capabilities
	fmt.Println("=== Internal Knowledge Base Service Capabilities ===")
	fmt.Println("Tools:")
	fmt.Println("  - search_docs: Search internal documentation")
	fmt.Println("  - get_doc_summary: Get a summary of a document")
	fmt.Println("  - create_page: Create a new page in the knowledge base")
	fmt.Println("  - list_recent_updates: List recently updated documents for a team")
	fmt.Println("Resources:")
	fmt.Println("  - docs://{doc_id}: Document")
	fmt.Println("===================================")

	// Start StreamableHTTP server
	log.Println("Starting Internal Knowledge Base Service on :8084")
	httpServer := server.NewStreamableHTTPServer(s)
	if err := httpServer.Start(":8084"); err != nil {
		log.Fatal(err)
	}
}

func handleSearchDocs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query := req.GetString("query", "")
	if query == "" {
		return nil, fmt.Errorf("query is required")
	}

	// Search documents
	docs, err := searchDocsInKB(query)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Build JSON response
	var docsJSON string
	for i, d := range docs {
		if i > 0 {
			docsJSON += ","
		}
		docsJSON += fmt.Sprintf(`{"id":"%s","title":"%s","team":"%s","lastUpdated":"%s","excerpt":"%s"}`,
			d.ID, d.Title, d.Team, d.LastUpdated.Format(time.RFC3339), truncateExcerpt(d.Body, 100))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"documents":[%s],"total":%d,"query":"%s"}`,
		docsJSON, len(docs), query)), nil
}

func handleGetDocSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	docID := req.GetString("doc_id", "")
	if docID == "" {
		return nil, fmt.Errorf("doc_id is required")
	}

	// Get document
	doc, err := getDocFromKB(docID)
	if err != nil {
		return nil, fmt.Errorf("document not found: %s", docID)
	}

	// Generate summary
	summary := generateSummary(doc)

	return mcp.NewToolResultText(fmt.Sprintf(`{
		"id":"%s",
		"title":"%s",
		"team":"%s",
		"author":"%s",
		"lastUpdated":"%s",
		"summary":"%s"
	}`,
		doc.ID, doc.Title, doc.Team, doc.Author, doc.LastUpdated.Format(time.RFC3339), summary)), nil
}

func handleCreatePage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	title := req.GetString("title", "")
	body := req.GetString("body", "")

	if title == "" || body == "" {
		return nil, fmt.Errorf("title and body are required")
	}

	// Create document
	doc := &Document{
		ID:          generateID(),
		Title:       title,
		Body:        body,
		Team:        "General", // Default team
		Author:      "System",  // Default author
		CreatedAt:   time.Now(),
		LastUpdated: time.Now(),
	}

	if err := saveDocToKB(doc); err != nil {
		return nil, fmt.Errorf("failed to create document: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"id":"%s","message":"Document created successfully","document":{"id":"%s","title":"%s","team":"%s"}}`,
		doc.ID, doc.ID, doc.Title, doc.Team)), nil
}

func handleListRecentUpdates(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	team := req.GetString("team", "")
	if team == "" {
		return nil, fmt.Errorf("team is required")
	}

	// Get recent updates
	docs, err := getRecentUpdates(team)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent updates: %w", err)
	}

	// Build JSON response
	var docsJSON string
	for i, d := range docs {
		if i > 0 {
			docsJSON += ","
		}
		docsJSON += fmt.Sprintf(`{"id":"%s","title":"%s","author":"%s","lastUpdated":"%s"}`,
			d.ID, d.Title, d.Author, d.LastUpdated.Format(time.RFC3339))
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"documents":[%s],"total":%d,"team":"%s"}`,
		docsJSON, len(docs), team)), nil
}

func handleDocResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	docID := extractDocIDFromURI(req.Params.URI)

	doc, err := getDocFromKB(docID)
	if err != nil {
		return nil, fmt.Errorf("document not found: %s", docID)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text: fmt.Sprintf(`{
				"id":"%s",
				"title":"%s",
				"body":"%s",
				"team":"%s",
				"author":"%s",
				"created_at":"%s",
				"last_updated":"%s"
			}`,
				doc.ID, doc.Title, escapeJSON(doc.Body), doc.Team, doc.Author,
				doc.CreatedAt.Format(time.RFC3339), doc.LastUpdated.Format(time.RFC3339)),
		},
	}, nil
}

// Helper functions and types
type Document struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Body        string    `json:"body"`
	Team        string    `json:"team"`
	Author      string    `json:"author"`
	CreatedAt   time.Time `json:"created_at"`
	LastUpdated time.Time `json:"last_updated"`
}

func getDocFromKB(docID string) (*Document, error) {
	// Placeholder implementation
	// In a real implementation, this would query a database
	
	// Return different mock documents based on ID
	switch docID {
	case "doc_1":
		return &Document{
			ID:          docID,
			Title:       "Employee PTO Policy",
			Body:        "# PTO Policy\n\nAll full-time employees are eligible for Paid Time Off (PTO). PTO accrues at a rate of 1.5 days per month, totaling 18 days per year. Employees may carry over up to 5 days of unused PTO to the next calendar year.\n\n## Requesting PTO\n\nEmployees should submit PTO requests through the HR portal at least 2 weeks in advance for planned absences. For unexpected absences, employees should notify their manager as soon as possible.\n\n## Approval Process\n\nPTO requests are subject to manager approval based on team workload and business needs.",
			Team:        "HR",
			Author:      "Sarah Johnson",
			CreatedAt:   time.Now().Add(-180 * 24 * time.Hour),
			LastUpdated: time.Now().Add(-15 * 24 * time.Hour),
		}, nil
	case "doc_2":
		return &Document{
			ID:          docID,
			Title:       "Q3 Product Roadmap",
			Body:        "# Q3 Product Roadmap\n\n## Key Initiatives\n\n1. **Mobile App Redesign** - Complete UI/UX overhaul of the mobile experience\n2. **API v2 Launch** - Release of our new API with improved performance and additional endpoints\n3. **Enterprise SSO Integration** - Support for SAML and OAuth 2.0\n\n## Timeline\n\n- July: Mobile App Design Finalization\n- August: API v2 Beta Release\n- September: Enterprise SSO Launch",
			Team:        "Product",
			Author:      "Michael Chen",
			CreatedAt:   time.Now().Add(-45 * 24 * time.Hour),
			LastUpdated: time.Now().Add(-3 * 24 * time.Hour),
		}, nil
	case "doc_3":
		return &Document{
			ID:          docID,
			Title:       "Sales Enablement Guide",
			Body:        "# Sales Enablement Guide\n\n## Competitive Analysis\n\nThis document provides a detailed comparison of our product against key competitors in the market.\n\n## Pricing Strategy\n\nOur pricing strategy is based on a tiered approach:\n\n- Basic: $10/user/month\n- Professional: $25/user/month\n- Enterprise: Custom pricing\n\n## Objection Handling\n\nCommon customer objections and recommended responses:\n\n1. \"Your solution is too expensive\" - Focus on ROI and total value delivered\n2. \"We're already using Competitor X\" - Highlight our unique features and integration capabilities",
			Team:        "Sales",
			Author:      "Jessica Williams",
			CreatedAt:   time.Now().Add(-60 * 24 * time.Hour),
			LastUpdated: time.Now().Add(-10 * 24 * time.Hour),
		}, nil
	case "doc_4":
		return &Document{
			ID:          docID,
			Title:       "Remote Work Guidelines",
			Body:        "# Remote Work Guidelines\n\n## Eligibility\n\nAll employees are eligible for hybrid work arrangements, with a minimum of 2 days per week in the office.\n\n## Equipment\n\nThe company provides a laptop, monitor, and peripherals for home office use. Additional equipment requests can be submitted to IT.\n\n## Communication Expectations\n\n- Maintain availability during core hours (10am-3pm local time)\n- Respond to Slack messages within 2 hours during working hours\n- Update calendar with working hours and availability\n\n## Security Requirements\n\n- Use company VPN when accessing internal systems\n- Ensure home WiFi is password protected\n- Lock computer when stepping away",
			Team:        "HR",
			Author:      "David Thompson",
			CreatedAt:   time.Now().Add(-120 * 24 * time.Hour),
			LastUpdated: time.Now().Add(-5 * 24 * time.Hour),
		}, nil
	case "doc_5":
		return &Document{
			ID:          docID,
			Title:       "Engineering Onboarding",
			Body:        "# Engineering Onboarding\n\n## First Week\n\n- Setup development environment\n- Complete security training\n- Review architecture documentation\n- Complete first PR (usually a documentation update)\n\n## First Month\n\n- Shadow on-call rotation\n- Complete service ownership training\n- Contribute to at least one feature\n\n## Resources\n\n- Internal GitHub: github.internal.company.com\n- CI/CD Pipeline: jenkins.company.com\n- Documentation: docs.company.com",
			Team:        "Engineering",
			Author:      "Alex Rodriguez",
			CreatedAt:   time.Now().Add(-90 * 24 * time.Hour),
			LastUpdated: time.Now().Add(-20 * 24 * time.Hour),
		}, nil
	default:
		// For any other ID, generate a document based on the ID
		return &Document{
			ID:          docID,
			Title:       "Generated Document",
			Body:        fmt.Sprintf("This is a generated document with ID %s. It contains placeholder content.", docID),
			Team:        "General",
			Author:      "System",
			CreatedAt:   time.Now().Add(-30 * 24 * time.Hour),
			LastUpdated: time.Now().Add(-1 * 24 * time.Hour),
		}, nil
	}
}

func generateID() string {
	// Placeholder implementation
	return fmt.Sprintf("doc_%d", time.Now().UnixNano())
}

func saveDocToKB(doc *Document) error {
	// Placeholder implementation
	// In a real implementation, this would save to a database
	return nil
}

func searchDocsInKB(query string) ([]*Document, error) {
	// Placeholder implementation
	// In a real implementation, this would search a database
	docs := []*Document{
		{
			ID:          "doc_1",
			Title:       "Employee PTO Policy",
			Body:        "# PTO Policy\n\nAll full-time employees are eligible for Paid Time Off (PTO)...",
			Team:        "HR",
			Author:      "Sarah Johnson",
			LastUpdated: time.Now().Add(-15 * 24 * time.Hour),
		},
		{
			ID:          "doc_2",
			Title:       "Q3 Product Roadmap",
			Body:        "# Q3 Product Roadmap\n\n## Key Initiatives\n\n1. **Mobile App Redesign**...",
			Team:        "Product",
			Author:      "Michael Chen",
			LastUpdated: time.Now().Add(-3 * 24 * time.Hour),
		},
		{
			ID:          "doc_3",
			Title:       "Sales Enablement Guide",
			Body:        "# Sales Enablement Guide\n\n## Competitive Analysis\n\nThis document provides...",
			Team:        "Sales",
			Author:      "Jessica Williams",
			LastUpdated: time.Now().Add(-10 * 24 * time.Hour),
		},
		{
			ID:          "doc_4",
			Title:       "Remote Work Guidelines",
			Body:        "# Remote Work Guidelines\n\n## Eligibility\n\nAll employees are eligible for hybrid work...",
			Team:        "HR",
			Author:      "David Thompson",
			LastUpdated: time.Now().Add(-5 * 24 * time.Hour),
		},
		{
			ID:          "doc_5",
			Title:       "Engineering Onboarding",
			Body:        "# Engineering Onboarding\n\n## First Week\n\n- Setup development environment...",
			Team:        "Engineering",
			Author:      "Alex Rodriguez",
			LastUpdated: time.Now().Add(-20 * 24 * time.Hour),
		},
		{
			ID:          "doc_6",
			Title:       "API Security Guidelines",
			Body:        "# API Security Guidelines\n\n## Authentication\n\nAll APIs must implement JWT-based authentication with proper token validation...",
			Team:        "Security",
			Author:      "Diana Cooper",
			LastUpdated: time.Now().Add(-8 * 24 * time.Hour),
		},
		{
			ID:          "doc_7",
			Title:       "Database Migration Procedures",
			Body:        "# Database Migration Procedures\n\n## Pre-Migration Checklist\n\n1. Create full database backup\n2. Verify migration scripts in staging...",
			Team:        "Engineering",
			Author:      "Thomas Lee",
			LastUpdated: time.Now().Add(-12 * 24 * time.Hour),
		},
		{
			ID:          "doc_8",
			Title:       "Customer Success Playbook",
			Body:        "# Customer Success Playbook\n\n## Onboarding Process\n\nNew customers should receive welcome email within 24 hours...",
			Team:        "Customer Success",
			Author:      "Maria Santos",
			LastUpdated: time.Now().Add(-6 * 24 * time.Hour),
		},
		{
			ID:          "doc_9",
			Title:       "Code Review Standards",
			Body:        "# Code Review Standards\n\n## Review Criteria\n\n- Code follows established style guide\n- All functions have proper documentation...",
			Team:        "Engineering",
			Author:      "Ryan Kim",
			LastUpdated: time.Now().Add(-18 * 24 * time.Hour),
		},
		{
			ID:          "doc_10",
			Title:       "Marketing Campaign Guidelines",
			Body:        "# Marketing Campaign Guidelines\n\n## Brand Voice\n\nOur brand voice should be professional yet approachable...",
			Team:        "Marketing",
			Author:      "Jennifer Walsh",
			LastUpdated: time.Now().Add(-4 * 24 * time.Hour),
		},
		{
			ID:          "doc_11",
			Title:       "Incident Response Plan",
			Body:        "# Incident Response Plan\n\n## Severity Levels\n\n- P0: Complete service outage\n- P1: Major feature unavailable\n- P2: Minor degradation...",
			Team:        "Engineering",
			Author:      "Carlos Mendez",
			LastUpdated: time.Now().Add(-7 * 24 * time.Hour),
		},
		{
			ID:          "doc_12",
			Title:       "Expense Reimbursement Policy",
			Body:        "# Expense Reimbursement Policy\n\n## Eligible Expenses\n\n- Business travel and accommodation\n- Client entertainment...",
			Team:        "Finance",
			Author:      "Patricia Davis",
			LastUpdated: time.Now().Add(-25 * 24 * time.Hour),
		},
		{
			ID:          "doc_13",
			Title:       "PDF Generation Service Troubleshooting",
			Body:        "# PDF Generation Service Troubleshooting\n\n## Common Issues\n\n### 502 Gateway Errors\n\n**Symptoms:** API returns 502 Bad Gateway when processing documents\n\n**Common Causes:**\n- Document size exceeds processing limits (>10MB)\n- Upstream service timeout due to high load\n- Memory exhaustion in processing pipeline\n\n**Resolution Steps:**\n1. Check service health in monitoring dashboard\n2. Review error logs for timeout patterns\n3. Scale up processing capacity if needed\n4. Contact Docs Infra Team for complex issues\n\n## Service Dependencies\n\n- Document Storage Service\n- PDF Rendering Engine\n- Load Balancer\n- File Upload Service\n\n## Emergency Contacts\n\n- Docs Infra Team: docs-infra@company.com\n- On-call Engineer: +1-555-0123\n\n## Known Issues\n\n- Large documents (>10MB) may timeout during peak hours\n- Complex layouts can cause memory spikes",
			Team:        "Engineering",
			Author:      "Alex Rodriguez",
			LastUpdated: time.Now().Add(-2 * 24 * time.Hour),
		},
	}
	
	// Filter by query (case-insensitive)
	queryLower := strings.ToLower(query)
	filtered := []*Document{}
	for _, d := range docs {
		if strings.Contains(strings.ToLower(d.Title), queryLower) ||
		   strings.Contains(strings.ToLower(d.Body), queryLower) ||
		   strings.Contains(strings.ToLower(d.Team), queryLower) {
			filtered = append(filtered, d)
		}
	}
	
	return filtered, nil
}

func getRecentUpdates(team string) ([]*Document, error) {
	// Placeholder implementation
	// In a real implementation, this would query a database
	allDocs := []*Document{
		{
			ID:          "doc_1",
			Title:       "Employee PTO Policy",
			Team:        "HR",
			Author:      "Sarah Johnson",
			LastUpdated: time.Now().Add(-15 * 24 * time.Hour),
		},
		{
			ID:          "doc_2",
			Title:       "Q3 Product Roadmap",
			Team:        "Product",
			Author:      "Michael Chen",
			LastUpdated: time.Now().Add(-3 * 24 * time.Hour),
		},
		{
			ID:          "doc_3",
			Title:       "Sales Enablement Guide",
			Team:        "Sales",
			Author:      "Jessica Williams",
			LastUpdated: time.Now().Add(-10 * 24 * time.Hour),
		},
		{
			ID:          "doc_4",
			Title:       "Remote Work Guidelines",
			Team:        "HR",
			Author:      "David Thompson",
			LastUpdated: time.Now().Add(-5 * 24 * time.Hour),
		},
		{
			ID:          "doc_5",
			Title:       "Engineering Onboarding",
			Team:        "Engineering",
			Author:      "Alex Rodriguez",
			LastUpdated: time.Now().Add(-20 * 24 * time.Hour),
		},
		{
			ID:          "doc_6",
			Title:       "API Security Guidelines",
			Team:        "Security",
			Author:      "Diana Cooper",
			LastUpdated: time.Now().Add(-8 * 24 * time.Hour),
		},
		{
			ID:          "doc_7",
			Title:       "Database Migration Procedures",
			Team:        "Engineering",
			Author:      "Thomas Lee",
			LastUpdated: time.Now().Add(-12 * 24 * time.Hour),
		},
		{
			ID:          "doc_8",
			Title:       "Customer Success Playbook",
			Team:        "Customer Success",
			Author:      "Maria Santos",
			LastUpdated: time.Now().Add(-6 * 24 * time.Hour),
		},
		{
			ID:          "doc_9",
			Title:       "Code Review Standards",
			Team:        "Engineering",
			Author:      "Ryan Kim",
			LastUpdated: time.Now().Add(-18 * 24 * time.Hour),
		},
		{
			ID:          "doc_10",
			Title:       "Marketing Campaign Guidelines",
			Team:        "Marketing",
			Author:      "Jennifer Walsh",
			LastUpdated: time.Now().Add(-4 * 24 * time.Hour),
		},
		{
			ID:          "doc_11",
			Title:       "Incident Response Plan",
			Team:        "Engineering",
			Author:      "Carlos Mendez",
			LastUpdated: time.Now().Add(-7 * 24 * time.Hour),
		},
		{
			ID:          "doc_12",
			Title:       "Expense Reimbursement Policy",
			Team:        "Finance",
			Author:      "Patricia Davis",
			LastUpdated: time.Now().Add(-25 * 24 * time.Hour),
		},
		{
			ID:          "doc_13",
			Title:       "PDF Generation Service Troubleshooting",
			Team:        "Engineering",
			Author:      "Alex Rodriguez",
			LastUpdated: time.Now().Add(-2 * 24 * time.Hour),
		},
	}
	
	// Filter by team
	filtered := []*Document{}
	for _, d := range allDocs {
		if d.Team == team {
			filtered = append(filtered, d)
		}
	}
	
	// Sort by last updated (most recent first)
	// In a real implementation, we would use a proper sorting algorithm
	// This is just a simple example
	if len(filtered) > 1 {
		for i := 0; i < len(filtered)-1; i++ {
			for j := i + 1; j < len(filtered); j++ {
				if filtered[j].LastUpdated.After(filtered[i].LastUpdated) {
					filtered[i], filtered[j] = filtered[j], filtered[i]
				}
			}
		}
	}
	
	return filtered, nil
}

func extractDocIDFromURI(uri string) string {
	// Extract document ID from URI like "docs://123"
	if len(uri) > 7 && uri[:7] == "docs://" {
		return uri[7:]
	}
	return uri
}

func truncateExcerpt(text string, maxLength int) string {
	if len(text) <= maxLength {
		return text
	}
	return text[:maxLength] + "..."
}

func generateSummary(doc *Document) string {
	// In a real implementation, this might use NLP to generate a summary
	// For this mock, we'll just return a simple summary based on the document
	
	switch doc.Team {
	case "HR":
		return "This HR document outlines company policies and procedures for employees."
	case "Product":
		return "This product document describes upcoming features and the product roadmap."
	case "Sales":
		return "This sales document provides guidance on sales strategies and customer engagement."
	case "Engineering":
		return "This engineering document contains technical specifications and development guidelines."
	default:
		return fmt.Sprintf("This document contains information related to %s.", doc.Title)
	}
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}
