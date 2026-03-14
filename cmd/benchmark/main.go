package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mark-liu/webguard-mcp/internal/classify"
	"github.com/mark-liu/webguard-mcp/internal/fetch"
)

type BenchResult struct {
	URL         string  `json:"url"`
	FetchMS     float64 `json:"fetch_ms"`
	ExtractMS   float64 `json:"extract_ms"`
	ScanMS      float64 `json:"scan_ms"`
	TotalMS     float64 `json:"total_ms"`
	OverheadMS  float64 `json:"overhead_ms"`
	OverheadPct float64 `json:"overhead_pct"`
	ContentLen  int     `json:"content_length"`
	Verdict     string  `json:"verdict"`
	Score       float64 `json:"score"`
	Matches     int     `json:"matches"`
	Error       string  `json:"error,omitempty"`
}

var defaultURLs = []string{
	"https://example.com",
	"https://www.rust-lang.org/",
	"https://news.ycombinator.com/",
	"https://pkg.go.dev/std",
	"https://docs.python.org/3/",
	"https://www.canton.network/developer-resources",
}

func main() {
	jsonOutput := flag.Bool("json", false, "output as JSON")
	flag.Parse()

	urls := defaultURLs
	if flag.NArg() > 0 {
		urls = flag.Args()
	}

	engine := classify.NewEngine(classify.SensitivityMedium)
	var results []BenchResult

	for _, url := range urls {
		result := benchURL(engine, url)
		results = append(results, result)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	} else {
		// Print as markdown table
		fmt.Println("| URL | Fetch (ms) | Extract (ms) | Scan (ms) | Total (ms) | Overhead | Content | Verdict | Score | Matches |")
		fmt.Println("|-----|-----------|-------------|----------|-----------|---------|---------|---------|-------|---------|")
		for _, r := range results {
			if r.Error != "" {
				fmt.Printf("| %s | - | - | - | - | - | - | ERROR | - | %s |\n", truncURL(r.URL, 40), r.Error)
				continue
			}
			fmt.Printf("| %s | %.1f | %.1f | %.1f | %.1f | %.1f%% | %s | %s | %.2f | %d |\n",
				truncURL(r.URL, 40), r.FetchMS, r.ExtractMS, r.ScanMS, r.TotalMS,
				r.OverheadPct, humanSize(r.ContentLen), r.Verdict, r.Score, r.Matches)
		}
	}
}

func benchURL(engine *classify.Engine, rawURL string) BenchResult {
	result := BenchResult{URL: rawURL}

	// Fetch
	fetchStart := time.Now()
	fetchResult, err := fetch.Fetch(context.Background(), rawURL, fetch.DefaultOptions())
	result.FetchMS = float64(time.Since(fetchStart).Microseconds()) / 1000.0

	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Extract
	extractStart := time.Now()
	content, err := fetch.Extract(fetchResult.Body, fetchResult.ContentType)
	result.ExtractMS = float64(time.Since(extractStart).Microseconds()) / 1000.0

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.ContentLen = len(content)

	// Classify
	scanStart := time.Now()
	classResult := engine.Classify(content)
	result.ScanMS = float64(time.Since(scanStart).Microseconds()) / 1000.0

	result.TotalMS = result.FetchMS + result.ExtractMS + result.ScanMS
	result.OverheadMS = result.ExtractMS + result.ScanMS
	if result.FetchMS > 0 {
		result.OverheadPct = (result.OverheadMS / result.FetchMS) * 100
	}
	result.Verdict = string(classResult.Verdict)
	result.Score = classResult.Score
	result.Matches = len(classResult.Matches)

	return result
}

func truncURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen-3] + "..."
}

func humanSize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
}
