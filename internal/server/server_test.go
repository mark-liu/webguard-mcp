package server

import (
	"net/url"
	"testing"

	"github.com/mark-liu/webguard-mcp/internal/audit"
	"github.com/mark-liu/webguard-mcp/internal/classify"
	"github.com/mark-liu/webguard-mcp/internal/config"
)

func TestReloadConfig(t *testing.T) {
	cfg := config.Default()
	logger, _ := audit.New("", false)
	srv := New(cfg, logger, "test")

	// Verify initial config
	got := srv.getConfig()
	if got.Sensitivity != "medium" {
		t.Fatalf("expected medium, got %s", got.Sensitivity)
	}

	// Reload with different config
	newCfg := config.Default()
	newCfg.Sensitivity = "high"
	newCfg.Blocklist = []string{"*.evil.com"}
	srv.ReloadConfig(newCfg)

	// Verify swapped
	got = srv.getConfig()
	if got.Sensitivity != "high" {
		t.Errorf("expected high after reload, got %s", got.Sensitivity)
	}
	if len(got.Blocklist) != 1 {
		t.Errorf("expected 1 blocklist entry, got %d", len(got.Blocklist))
	}
}

func TestReloadConfig_ConcurrentReads(t *testing.T) {
	cfg := config.Default()
	logger, _ := audit.New("", false)
	srv := New(cfg, logger, "test")

	done := make(chan bool, 100)

	// 50 concurrent readers
	for range 50 {
		go func() {
			for range 100 {
				c := srv.getConfig()
				_ = c.Sensitivity
			}
			done <- true
		}()
	}

	// 50 concurrent reloads
	for range 50 {
		go func() {
			for range 100 {
				newCfg := config.Default()
				srv.ReloadConfig(newCfg)
			}
			done <- true
		}()
	}

	for range 100 {
		<-done
	}
}

func TestGetConfig_SnapshotConsistency(t *testing.T) {
	cfg := config.Default()
	cfg.Sensitivity = "low"
	cfg.Blocklist = []string{"a.com", "b.com"}
	logger, _ := audit.New("", false)
	srv := New(cfg, logger, "test")

	// Grab snapshot
	snapshot := srv.getConfig()

	// Reload with different config
	newCfg := config.Default()
	newCfg.Sensitivity = "high"
	newCfg.Blocklist = nil
	srv.ReloadConfig(newCfg)

	// Snapshot should still reflect the old config
	if snapshot.Sensitivity != "low" {
		t.Errorf("snapshot mutated: expected low, got %s", snapshot.Sensitivity)
	}
	if len(snapshot.Blocklist) != 2 {
		t.Errorf("snapshot mutated: expected 2 blocklist entries, got %d", len(snapshot.Blocklist))
	}
}

func TestIsDocURL(t *testing.T) {
	tests := []struct {
		rawURL string
		want   bool
	}{
		{"https://example.com/docs/api", true},
		{"https://example.com/api/v2/endpoint", true},
		{"https://example.com/reference/types", true},
		{"https://example.com/developer/getting-started", true},
		{"https://example.com/guide/intro", true},
		{"https://example.com/sdk/go", true},
		{"https://example.com/tutorial/basics", true},
		{"https://example.com/blog/post", false},
		{"https://example.com/", false},
		{"https://example.com/careers", false},
	}

	for _, tc := range tests {
		t.Run(tc.rawURL, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			got := isDocURL(u)
			if got != tc.want {
				t.Errorf("isDocURL(%q) = %v, want %v", tc.rawURL, got, tc.want)
			}
		})
	}
}

func TestFormatMatchCategories(t *testing.T) {
	matches := []classify.Match{
		{Category: "authority-claim"},
		{Category: "instruction-override"},
		{Category: "authority-claim"},
	}

	got := formatMatchCategories(matches)
	// Should be sorted alphabetically.
	if got != "authority-claim:2, instruction-override:1" {
		t.Errorf("formatMatchCategories = %q", got)
	}
}

func TestFormatMatchCategories_Empty(t *testing.T) {
	got := formatMatchCategories(nil)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestPct(t *testing.T) {
	if got := pct(50, 100); got != 50.0 {
		t.Errorf("pct(50, 100) = %f, want 50.0", got)
	}
	if got := pct(0, 0); got != 0 {
		t.Errorf("pct(0, 0) = %f, want 0", got)
	}
}

func TestSortedMapDesc(t *testing.T) {
	m := map[string]int{
		"a": 1,
		"b": 3,
		"c": 2,
	}
	sorted := sortedMapDesc(m)
	if len(sorted) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(sorted))
	}
	if sorted[0].key != "b" || sorted[0].value != 3 {
		t.Errorf("first entry = %v, want {b, 3}", sorted[0])
	}
	if sorted[1].key != "c" || sorted[1].value != 2 {
		t.Errorf("second entry = %v, want {c, 2}", sorted[1])
	}
}

func TestExternalPatterns_StoredInServer(t *testing.T) {
	cfg := config.Default()
	logger, _ := audit.New("", false)
	srv := New(cfg, logger, "test")

	// Default: no external patterns.
	if len(srv.getExternalPatterns()) != 0 {
		t.Errorf("expected 0 external patterns, got %d", len(srv.getExternalPatterns()))
	}
}
