package server

import (
	"testing"

	"github.com/mark-liu/webguard-mcp/internal/audit"
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
