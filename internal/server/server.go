package server

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mark-liu/webguard-mcp/internal/audit"
	"github.com/mark-liu/webguard-mcp/internal/classify"
	"github.com/mark-liu/webguard-mcp/internal/config"
	"github.com/mark-liu/webguard-mcp/internal/fetch"
)

// Server wraps the MCP server with webguard classification and fetching.
type Server struct {
	config  *config.Config
	audit   *audit.Logger
	version string
	mcp     *mcpserver.MCPServer
}

// New creates a Server with tools registered and ready to run.
func New(cfg *config.Config, auditLogger *audit.Logger, version string) *Server {
	s := &Server{
		config:  cfg,
		audit:   auditLogger,
		version: version,
	}

	s.mcp = mcpserver.NewMCPServer(
		"webguard-mcp",
		version,
		mcpserver.WithToolCapabilities(false),
	)

	s.registerTools()
	return s
}

// Run starts the MCP server on stdio transport. It blocks until the
// transport is closed or an error occurs.
func (s *Server) Run() error {
	return mcpserver.ServeStdio(s.mcp)
}

// registerTools adds the webguard_fetch and webguard_status tools.
func (s *Server) registerTools() {
	s.mcp.AddTool(
		mcp.NewTool("webguard_fetch",
			mcp.WithDescription(
				"Fetch a web page with SSRF protection and prompt-injection scanning. "+
					"Returns the page content as markdown (default) or raw HTML, with a "+
					"webguard metadata block appended. Content from pages that contain "+
					"prompt injection is blocked entirely.",
			),
			mcp.WithString("url",
				mcp.Required(),
				mcp.Description("The URL to fetch (http or https)"),
			),
			mcp.WithObject("headers",
				mcp.Description("Optional HTTP headers to send with the request"),
			),
			mcp.WithBoolean("raw",
				mcp.Description("If true, return raw HTML instead of converted markdown"),
			),
		),
		s.handleFetch,
	)

	s.mcp.AddTool(
		mcp.NewTool("webguard_status",
			mcp.WithDescription(
				"Return the current webguard-mcp server status including version, "+
					"configuration, pattern count, and audit settings.",
			),
		),
		s.handleStatus,
	)
}

// handleFetch implements the webguard_fetch tool.
func (s *Server) handleFetch(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	totalStart := time.Now()

	// --- Parse arguments ---
	rawURL, err := request.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError("missing required parameter: url"), nil
	}

	customHeaders := mcp.ParseStringMap(request, "headers", nil)
	raw := mcp.ParseBoolean(request, "raw", false)

	// --- Extract domain for config lookups ---
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid URL: %v", err)), nil
	}
	domain := strings.ToLower(parsed.Hostname())

	// --- Check blocklist ---
	if s.config.IsBlocked(domain) {
		s.logAuditEntry(rawURL, "block", 0, nil, 0, 0, 0, "domain is blocklisted")
		return mcp.NewToolResultText(
			fmt.Sprintf("[BLOCKED: domain %q is on the blocklist]", domain),
		), nil
	}

	// --- Check allowlist ---
	if !s.config.IsAllowed(domain) {
		s.logAuditEntry(rawURL, "block", 0, nil, 0, 0, 0, "domain not on allowlist")
		return mcp.NewToolResultText(
			fmt.Sprintf("[BLOCKED: domain %q is not on the allowlist]", domain),
		), nil
	}

	// --- Build fetch options ---
	opts := fetch.FetchOptions{
		MaxBodySize: s.config.MaxBodySize,
		Timeout:     s.config.Timeout.Duration,
	}

	if len(customHeaders) > 0 {
		opts.Headers = make(map[string]string, len(customHeaders))
		for k, v := range customHeaders {
			if sv, ok := v.(string); ok {
				opts.Headers[k] = sv
			}
		}
	}

	// --- Fetch ---
	fetchStart := time.Now()
	result, err := fetch.Fetch(ctx, rawURL, opts)
	fetchElapsed := time.Since(fetchStart)

	if err != nil {
		s.logAuditEntry(rawURL, "error", 0, nil, fetchElapsed, 0, time.Since(totalStart), err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("fetch failed: %v", err)), nil
	}

	// --- Extract content ---
	var content string
	if raw {
		content = string(result.Body)
	} else {
		extracted, err := fetch.Extract(result.Body, result.ContentType)
		if err != nil {
			s.logAuditEntry(rawURL, "error", 0, nil, fetchElapsed, 0, time.Since(totalStart), err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("content extraction failed: %v", err)), nil
		}
		content = extracted
	}

	// --- Classify ---
	sensitivity := classify.Sensitivity(s.config.SensitivityForDomain(domain))
	engine := classify.NewEngine(sensitivity)

	scanStart := time.Now()
	classification := engine.Classify(content)
	scanElapsed := time.Since(scanStart)

	totalElapsed := time.Since(totalStart)

	// --- Build metadata block ---
	meta := formatMetadata(
		string(classification.Verdict),
		classification.Score,
		len(classification.Matches),
		fetchElapsed,
		scanElapsed,
		result.FinalURL,
	)

	// --- Build audit match summaries ---
	var matchSummaries []audit.MatchSummary
	for _, m := range classification.Matches {
		matchSummaries = append(matchSummaries, audit.MatchSummary{
			PatternID: m.PatternID,
			Category:  m.Category,
			Severity:  string(m.Severity),
		})
	}

	// --- Handle verdict ---
	if classification.Verdict == classify.VerdictBlock {
		blockMsg := fmt.Sprintf(
			"[BLOCKED: prompt injection detected in content from %s]\n%s",
			rawURL, meta,
		)
		s.logAuditEntry(
			rawURL, "block", classification.Score, matchSummaries,
			fetchElapsed, scanElapsed, totalElapsed, "",
		)
		return mcp.NewToolResultText(blockMsg), nil
	}

	// --- Pass: return content + metadata ---
	s.logAuditEntry(
		rawURL, "pass", classification.Score, matchSummaries,
		fetchElapsed, scanElapsed, totalElapsed, "",
	)

	return mcp.NewToolResultText(content + "\n" + meta), nil
}

// handleStatus implements the webguard_status tool.
func (s *Server) handleStatus(
	_ context.Context,
	_ mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	// Build a classifier just to read pattern count.
	engine := classify.NewEngine(classify.Sensitivity(s.config.Sensitivity))

	auditPath := s.config.Audit.Path
	if auditPath == "" {
		auditPath = audit.DefaultPath()
	}

	status := fmt.Sprintf(
		"webguard-mcp status\n"+
			"  version:      %s\n"+
			"  sensitivity:  %s\n"+
			"  patterns:     %d\n"+
			"  max_body:     %d bytes\n"+
			"  timeout:      %s\n"+
			"  allowlist:    %d entries\n"+
			"  blocklist:    %d entries\n"+
			"  domains:      %d overrides\n"+
			"  audit:        enabled=%v path=%s",
		s.version,
		s.config.Sensitivity,
		engine.PatternCount(),
		s.config.MaxBodySize,
		s.config.Timeout.Duration,
		len(s.config.Allowlist),
		len(s.config.Blocklist),
		len(s.config.Domains),
		s.config.Audit.Enabled,
		auditPath,
	)

	return mcp.NewToolResultText(status), nil
}

// formatMetadata builds the YAML-like metadata block appended to tool output.
func formatMetadata(
	verdict string,
	score float64,
	matchCount int,
	fetchDur, scanDur time.Duration,
	finalURL string,
) string {
	return fmt.Sprintf(
		"---\nwebguard:\n"+
			"  verdict: %s\n"+
			"  score: %.1f\n"+
			"  matches: %d\n"+
			"  fetch_ms: %.1f\n"+
			"  scan_ms: %.1f\n"+
			"  url: %s",
		verdict,
		score,
		matchCount,
		float64(fetchDur.Microseconds())/1000.0,
		float64(scanDur.Microseconds())/1000.0,
		finalURL,
	)
}

// logAuditEntry writes an audit record if the audit logger is configured.
func (s *Server) logAuditEntry(
	url, verdict string,
	score float64,
	matches []audit.MatchSummary,
	fetchDur, scanDur, totalDur time.Duration,
	errMsg string,
) {
	s.audit.Log(audit.Entry{
		Timestamp:   time.Now(),
		URL:         url,
		Verdict:     verdict,
		Score:       score,
		Matches:     matches,
		FetchTimeMS: float64(fetchDur.Microseconds()) / 1000.0,
		ScanTimeMS:  float64(scanDur.Microseconds()) / 1000.0,
		TotalTimeMS: float64(totalDur.Microseconds()) / 1000.0,
		Error:       errMsg,
	})
}
