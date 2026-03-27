package server

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mark-liu/webguard-mcp/internal/audit"
	"github.com/mark-liu/webguard-mcp/internal/classify"
	"github.com/mark-liu/webguard-mcp/internal/config"
	"github.com/mark-liu/webguard-mcp/internal/fetch"
)

// docPathPatterns are URL path segments that indicate documentation content.
// When matched, exfil-instruction and encoded-injection categories are
// auto-suppressed to reduce false positives on legitimate API/SDK docs.
var docPathPatterns = []string{
	"/docs/", "/api/", "/reference/", "/developer/",
	"/documentation/", "/guide/", "/tutorial/", "/manual/",
	"/sdk/", "/spec/", "/specification/",
}

// Server wraps the MCP server with webguard classification and fetching.
type Server struct {
	mu               sync.RWMutex
	config           *config.Config
	audit            *audit.Logger
	version          string
	mcp              *mcpserver.MCPServer
	externalPatterns []classify.Pattern
}

// New creates a Server with tools registered and ready to run.
func New(cfg *config.Config, auditLogger *audit.Logger, version string) *Server {
	s := &Server{
		config:  cfg,
		audit:   auditLogger,
		version: version,
	}

	// Load external patterns if configured.
	if cfg.PatternsDir != "" {
		extra, err := classify.LoadExternalPatterns(cfg.PatternsDir)
		if err != nil {
			log.Printf("warning: failed to load external patterns: %v", err)
		} else if len(extra) > 0 {
			s.externalPatterns = extra
			log.Printf("loaded %d external patterns from %s", len(extra), cfg.PatternsDir)
		}
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

// ReloadConfig atomically swaps the server's config under a write lock.
// If the new config has a patterns_dir, external patterns are reloaded.
func (s *Server) ReloadConfig(cfg *config.Config) {
	// Reload external patterns if configured.
	var extra []classify.Pattern
	if cfg.PatternsDir != "" {
		loaded, err := classify.LoadExternalPatterns(cfg.PatternsDir)
		if err != nil {
			log.Printf("SIGHUP: failed to reload external patterns: %v", err)
		} else {
			extra = loaded
		}
	}

	s.mu.Lock()
	old := s.config
	s.config = cfg
	if extra != nil {
		s.externalPatterns = extra
	}
	s.mu.Unlock()

	log.Printf("config reloaded: sensitivity=%s mode=%s allowlist=%d blocklist=%d domains=%d external_patterns=%d (was: sensitivity=%s allowlist=%d blocklist=%d domains=%d)",
		cfg.Sensitivity, cfg.Mode, len(cfg.Allowlist), len(cfg.Blocklist), len(cfg.Domains), len(extra),
		old.Sensitivity, len(old.Allowlist), len(old.Blocklist), len(old.Domains),
	)
}

// getConfig returns the current config under a read lock. Callers should
// capture the returned pointer into a local variable and use that for the
// duration of the request to get a consistent snapshot.
func (s *Server) getConfig() *config.Config {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()
	return cfg
}

// getExternalPatterns returns the current external patterns under a read lock.
func (s *Server) getExternalPatterns() []classify.Pattern {
	s.mu.RLock()
	p := s.externalPatterns
	s.mu.RUnlock()
	return p
}

// registerTools adds the webguard_fetch, webguard_status, and webguard_report tools.
func (s *Server) registerTools() {
	s.mcp.AddTool(
		mcp.NewTool("webguard_fetch",
			mcp.WithDescription(
				"Fetch a web page with SSRF protection and prompt-injection scanning. "+
					"Returns the page content as markdown (default) or raw HTML, with a "+
					"webguard metadata block appended. Content from pages that contain "+
					"prompt injection is blocked entirely (or warned, if mode=warn).",
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
			mcp.WithNumber("max_chars",
				mcp.Description("Maximum characters to return (0 = unlimited). Content is truncated with a marker if exceeded."),
			),
		),
		s.handleFetch,
	)

	s.mcp.AddTool(
		mcp.NewTool("webguard_status",
			mcp.WithDescription(
				"Return the current webguard-mcp server status including version, "+
					"configuration, pattern count, mode, and audit settings.",
			),
		),
		s.handleStatus,
	)

	s.mcp.AddTool(
		mcp.NewTool("webguard_report",
			mcp.WithDescription(
				"Return an audit report with usage statistics, verdict breakdown, "+
					"top triggered patterns, blocked/warned domains, and timing metrics.",
			),
			mcp.WithNumber("days",
				mcp.Description("Number of days to include in the report (default: 7)"),
			),
		),
		s.handleReport,
	)
}

// handleFetch implements the webguard_fetch tool.
func (s *Server) handleFetch(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	totalStart := time.Now()

	// Grab a consistent config snapshot for this request.
	cfg := s.getConfig()
	extra := s.getExternalPatterns()

	// --- Parse arguments ---
	rawURL, err := request.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError("missing required parameter: url"), nil
	}

	customHeaders := mcp.ParseStringMap(request, "headers", nil)
	raw := mcp.ParseBoolean(request, "raw", false)
	maxChars := mcp.ParseInt(request, "max_chars", 0)

	// --- Extract domain for config lookups ---
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid URL: %v", err)), nil
	}
	domain := strings.ToLower(parsed.Hostname())

	// --- Check blocklist ---
	if cfg.IsBlocked(domain) {
		s.logAuditEntry(rawURL, "block", 0, nil, 0, 0, 0, "domain is blocklisted")
		return mcp.NewToolResultText(
			fmt.Sprintf("[BLOCKED: domain %q is on the blocklist]", domain),
		), nil
	}

	// --- Check allowlist ---
	if !cfg.IsAllowed(domain) {
		s.logAuditEntry(rawURL, "block", 0, nil, 0, 0, 0, "domain not on allowlist")
		return mcp.NewToolResultText(
			fmt.Sprintf("[BLOCKED: domain %q is not on the allowlist]", domain),
		), nil
	}

	// --- Build fetch options with per-domain timeout ---
	timeout := cfg.TimeoutForDomain(domain)
	opts := fetch.FetchOptions{
		MaxBodySize: cfg.MaxBodySize,
		Timeout:     timeout,
	}

	if len(customHeaders) > 0 {
		opts.Headers = make(map[string]string, len(customHeaders))
		for k, v := range customHeaders {
			if sv, ok := v.(string); ok {
				opts.Headers[k] = sv
			}
		}
	}

	// --- Fetch with automatic retry on timeout ---
	fetchStart := time.Now()
	result, err := fetch.FetchWithRetry(ctx, rawURL, opts)
	fetchElapsed := time.Since(fetchStart)

	if err != nil {
		s.logAuditEntry(rawURL, "error", 0, nil, fetchElapsed, 0, time.Since(totalStart), err.Error())
		return mcp.NewToolResultError(fmt.Sprintf("fetch failed: %v", err)), nil
	}

	// --- Extract content ---
	// Full extraction (with boilerplate) is used for classification so the
	// security scanner sees all content including nav/footer where attackers
	// may embed payloads. Clean extraction (without boilerplate) is used for
	// the returned output to reduce context waste.
	var content string     // full content for classification
	var cleanContent string // boilerplate-stripped content for output
	if raw {
		content = string(result.Body)
		cleanContent = content
	} else {
		extracted, err := fetch.Extract(result.Body, result.ContentType)
		if err != nil {
			s.logAuditEntry(rawURL, "error", 0, nil, fetchElapsed, 0, time.Since(totalStart), err.Error())
			return mcp.NewToolResultError(fmt.Sprintf("content extraction failed: %v", err)), nil
		}
		content = extracted

		clean, err := fetch.ExtractClean(result.Body, result.ContentType)
		if err != nil {
			// Non-fatal: fall back to full content if clean extraction fails.
			cleanContent = content
		} else {
			cleanContent = clean
		}
	}

	// --- Build suppressed categories ---
	suppress := cfg.SuppressedCategoriesForDomain(domain)

	// Auto-suppress for documentation URLs to reduce false positives.
	if isDocURL(parsed) {
		if suppress == nil {
			suppress = make(map[string]bool)
		}
		suppress["exfil-instruction"] = true
		suppress["encoded-injection"] = true
	}

	// --- Classify ---
	sensitivity := classify.Sensitivity(cfg.SensitivityForDomain(domain))
	engine := classify.NewEngineWithPatterns(sensitivity, extra)

	scanStart := time.Now()
	classification := engine.ClassifyWithOptions(content, classify.ClassifyOptions{
		SuppressCategories: suppress,
	})
	scanElapsed := time.Since(scanStart)

	totalElapsed := time.Since(totalStart)

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
		if cfg.IsWarnMode() {
			// Warn mode: return clean content with a warning banner.
			warnBanner := fmt.Sprintf(
				"[WARNING: WebGuard detected potential prompt injection (score=%.1f, patterns: %s)]\n\n",
				classification.Score,
				formatMatchCategories(classification.Matches),
			)

			truncated := false
			originalLen := len(cleanContent)
			if maxChars > 0 && originalLen > maxChars {
				cleanContent = cleanContent[:maxChars] + fmt.Sprintf("\n\n[... truncated at %d chars (%d total) ...]", maxChars, originalLen)
				truncated = true
			}

			meta := formatMetadata("warn", classification.Score, classification.Matches, fetchElapsed, scanElapsed, result.FinalURL)
			if truncated {
				meta += fmt.Sprintf("\n  truncated: true\n  original_chars: %d", originalLen)
			}

			s.logAuditEntry(rawURL, "warn", classification.Score, matchSummaries, fetchElapsed, scanElapsed, totalElapsed, "")
			return mcp.NewToolResultText(warnBanner + cleanContent + "\n" + meta), nil
		}

		// Block mode (default).
		meta := formatMetadata("block", classification.Score, classification.Matches, fetchElapsed, scanElapsed, result.FinalURL)
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

	// --- Truncate if max_chars set ---
	truncated := false
	originalLen := len(cleanContent)
	if maxChars > 0 && originalLen > maxChars {
		cleanContent = cleanContent[:maxChars] + fmt.Sprintf("\n\n[... truncated at %d chars (%d total) ...]", maxChars, originalLen)
		truncated = true
	}

	// --- Pass: return clean content + metadata ---
	s.logAuditEntry(
		rawURL, "pass", classification.Score, matchSummaries,
		fetchElapsed, scanElapsed, totalElapsed, "",
	)

	meta := formatMetadata("pass", classification.Score, classification.Matches, fetchElapsed, scanElapsed, result.FinalURL)
	if truncated {
		meta += fmt.Sprintf("\n  truncated: true\n  original_chars: %d", originalLen)
	}

	return mcp.NewToolResultText(cleanContent + "\n" + meta), nil
}

// handleStatus implements the webguard_status tool.
func (s *Server) handleStatus(
	_ context.Context,
	_ mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	cfg := s.getConfig()
	extra := s.getExternalPatterns()

	// Build a classifier to read pattern count.
	engine := classify.NewEngineWithPatterns(classify.Sensitivity(cfg.Sensitivity), extra)

	auditPath := cfg.Audit.Path
	if auditPath == "" {
		auditPath = audit.DefaultPath()
	}

	mode := cfg.Mode
	if mode == "" {
		mode = "block"
	}

	status := fmt.Sprintf(
		"webguard-mcp status\n"+
			"  version:          %s\n"+
			"  sensitivity:      %s\n"+
			"  mode:             %s\n"+
			"  patterns:         %d (built-in: %d, external: %d)\n"+
			"  max_body:         %d bytes\n"+
			"  timeout:          %s\n"+
			"  allowlist:        %d entries\n"+
			"  blocklist:        %d entries\n"+
			"  domains:          %d overrides\n"+
			"  patterns_dir:     %s\n"+
			"  audit:            enabled=%v path=%s",
		s.version,
		cfg.Sensitivity,
		mode,
		engine.PatternCount(),
		engine.PatternCount()-len(extra),
		len(extra),
		cfg.MaxBodySize,
		cfg.Timeout.Duration,
		len(cfg.Allowlist),
		len(cfg.Blocklist),
		len(cfg.Domains),
		cfg.PatternsDir,
		cfg.Audit.Enabled,
		auditPath,
	)

	return mcp.NewToolResultText(status), nil
}

// handleReport implements the webguard_report tool.
func (s *Server) handleReport(
	_ context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	cfg := s.getConfig()

	days := mcp.ParseInt(request, "days", 7)
	since := time.Now().AddDate(0, 0, -days)

	auditPath := cfg.Audit.Path
	if auditPath == "" {
		auditPath = audit.DefaultPath()
	}

	entries, err := audit.ReadEntries(auditPath, since)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read audit log: %v", err)), nil
	}

	// Aggregate stats.
	total := len(entries)
	var pass, block, warn, errCount int
	patternHits := make(map[string]int)
	blockedDomains := make(map[string]int)
	var totalFetchMS, totalScanMS float64

	for _, e := range entries {
		switch e.Verdict {
		case "pass":
			pass++
		case "block":
			block++
			if u, uerr := url.Parse(e.URL); uerr == nil {
				blockedDomains[u.Hostname()]++
			}
		case "warn":
			warn++
			if u, uerr := url.Parse(e.URL); uerr == nil {
				blockedDomains[u.Hostname()]++
			}
		case "error":
			errCount++
		}

		for _, m := range e.Matches {
			patternHits[m.PatternID+" ("+m.Category+")"]++
		}

		totalFetchMS += e.FetchTimeMS
		totalScanMS += e.ScanTimeMS
	}

	// Build report.
	var b strings.Builder
	fmt.Fprintf(&b, "WebGuard Audit Report (last %d days)\n", days)
	fmt.Fprintf(&b, "  period: %s to %s\n", since.Format("2006-01-02"), time.Now().Format("2006-01-02"))
	fmt.Fprintf(&b, "  total:  %d\n", total)
	if total > 0 {
		fmt.Fprintf(&b, "  pass:   %d (%.1f%%)\n", pass, pct(pass, total))
		fmt.Fprintf(&b, "  block:  %d (%.1f%%)\n", block, pct(block, total))
		fmt.Fprintf(&b, "  warn:   %d (%.1f%%)\n", warn, pct(warn, total))
		fmt.Fprintf(&b, "  error:  %d (%.1f%%)\n", errCount, pct(errCount, total))
	}

	if len(patternHits) > 0 {
		fmt.Fprintf(&b, "\nTop triggered patterns:\n")
		for _, kv := range sortedMapDesc(patternHits) {
			fmt.Fprintf(&b, "  %s: %d\n", kv.key, kv.value)
		}
	}

	if len(blockedDomains) > 0 {
		fmt.Fprintf(&b, "\nTop blocked/warned domains:\n")
		for _, kv := range sortedMapDesc(blockedDomains) {
			fmt.Fprintf(&b, "  %s: %d\n", kv.key, kv.value)
		}
	}

	if total > 0 {
		fmt.Fprintf(&b, "\nAverage timing:\n")
		fmt.Fprintf(&b, "  fetch: %.1f ms\n", totalFetchMS/float64(total))
		fmt.Fprintf(&b, "  scan:  %.1f ms\n", totalScanMS/float64(total))
	}

	return mcp.NewToolResultText(b.String()), nil
}

// formatMetadata builds the YAML-like metadata block appended to tool output.
// Includes match details when patterns were detected (for both pass and block/warn).
func formatMetadata(
	verdict string,
	score float64,
	matches []classify.Match,
	fetchDur, scanDur time.Duration,
	finalURL string,
) string {
	s := fmt.Sprintf(
		"---\nwebguard:\n"+
			"  verdict: %s\n"+
			"  score: %.1f\n"+
			"  matches: %d\n"+
			"  fetch_ms: %.1f\n"+
			"  scan_ms: %.1f\n"+
			"  url: %s",
		verdict,
		score,
		len(matches),
		float64(fetchDur.Microseconds())/1000.0,
		float64(scanDur.Microseconds())/1000.0,
		finalURL,
	)

	if len(matches) > 0 {
		s += "\n  matched_patterns:"
		for _, m := range matches {
			s += fmt.Sprintf("\n    - %s (%s, %s)", m.PatternID, m.Category, m.Severity)
		}
	}

	return s
}

// formatMatchCategories returns a compact summary of matched categories
// for the warning banner.
func formatMatchCategories(matches []classify.Match) string {
	categories := make(map[string]int)
	for _, m := range matches {
		categories[m.Category]++
	}
	var parts []string
	for cat, count := range categories {
		parts = append(parts, fmt.Sprintf("%s:%d", cat, count))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// isDocURL checks whether the URL path indicates documentation content.
func isDocURL(u *url.URL) bool {
	path := strings.ToLower(u.Path)
	for _, p := range docPathPatterns {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
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

type kv struct {
	key   string
	value int
}

func sortedMapDesc(m map[string]int) []kv {
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].value > pairs[j].value
	})
	return pairs
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
