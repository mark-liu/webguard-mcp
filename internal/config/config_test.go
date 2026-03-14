package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Sensitivity != "medium" {
		t.Errorf("Sensitivity = %q, want %q", cfg.Sensitivity, "medium")
	}
	if cfg.MaxBodySize != 5<<20 {
		t.Errorf("MaxBodySize = %d, want %d", cfg.MaxBodySize, 5<<20)
	}
	if cfg.Timeout.Duration != 15*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout.Duration, 15*time.Second)
	}
	if !cfg.Audit.Enabled {
		t.Error("Audit.Enabled = false, want true")
	}
	if cfg.Audit.Path != "" {
		t.Errorf("Audit.Path = %q, want empty", cfg.Audit.Path)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Sensitivity != "medium" {
		t.Errorf("Sensitivity = %q, want %q", cfg.Sensitivity, "medium")
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `
sensitivity: high
max_body_size: 1048576
request_timeout: "30s"
domains:
  "example.com":
    sensitivity: low
  "*.evil.com":
    sensitivity: critical
allowlist:
  - "safe.com"
  - "*.trusted.org"
blocklist:
  - "bad.com"
audit:
  enabled: false
  path: /tmp/audit.jsonl
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Sensitivity != "high" {
		t.Errorf("Sensitivity = %q, want %q", cfg.Sensitivity, "high")
	}
	if cfg.MaxBodySize != 1048576 {
		t.Errorf("MaxBodySize = %d, want %d", cfg.MaxBodySize, 1048576)
	}
	if cfg.Timeout.Duration != 30*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout.Duration, 30*time.Second)
	}
	if cfg.Audit.Enabled {
		t.Error("Audit.Enabled = true, want false")
	}
	if cfg.Audit.Path != "/tmp/audit.jsonl" {
		t.Errorf("Audit.Path = %q, want %q", cfg.Audit.Path, "/tmp/audit.jsonl")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("{{invalid"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestSensitivityForDomain(t *testing.T) {
	cfg := Default()
	cfg.Domains = map[string]DomainConfig{
		"example.com":   {Sensitivity: "low"},
		"*.evil.com":    {Sensitivity: "critical"},
		"*.nested.evil": {Sensitivity: "high"},
	}

	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "low"},
		{"sub.evil.com", "critical"},
		{"deep.sub.evil.com", "critical"},
		{"evil.com", "medium"},         // wildcard does NOT match bare parent
		{"other.com", "medium"},        // falls back to global
		{"foo.nested.evil", "high"},
		{"nested.evil", "medium"},      // bare parent, no match
		{"EXAMPLE.COM", "low"},         // case insensitive
		{"Sub.Evil.Com", "critical"},   // case insensitive wildcard
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			got := cfg.SensitivityForDomain(tc.domain)
			if got != tc.want {
				t.Errorf("SensitivityForDomain(%q) = %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name      string
		allowlist []string
		domain    string
		want      bool
	}{
		{"empty allowlist allows all", nil, "anything.com", true},
		{"exact match", []string{"safe.com"}, "safe.com", true},
		{"no match", []string{"safe.com"}, "other.com", false},
		{"wildcard match", []string{"*.trusted.org"}, "sub.trusted.org", true},
		{"wildcard no bare", []string{"*.trusted.org"}, "trusted.org", false},
		{"case insensitive", []string{"Safe.Com"}, "safe.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Allowlist = tc.allowlist
			got := cfg.IsAllowed(tc.domain)
			if got != tc.want {
				t.Errorf("IsAllowed(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestIsBlocked(t *testing.T) {
	tests := []struct {
		name      string
		blocklist []string
		domain    string
		want      bool
	}{
		{"empty blocklist blocks none", nil, "anything.com", false},
		{"exact match", []string{"bad.com"}, "bad.com", true},
		{"no match", []string{"bad.com"}, "good.com", false},
		{"wildcard match", []string{"*.malware.net"}, "x.malware.net", true},
		{"wildcard no bare", []string{"*.malware.net"}, "malware.net", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Blocklist = tc.blocklist
			got := cfg.IsBlocked(tc.domain)
			if got != tc.want {
				t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestDuration_MarshalYAML(t *testing.T) {
	d := Duration{30 * time.Second}
	v, err := d.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML: %v", err)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("MarshalYAML returned %T, want string", v)
	}
	if s != "30s" {
		t.Errorf("MarshalYAML = %q, want %q", s, "30s")
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", false},
		{"example.com", "example.com", false}, // not a wildcard pattern
		{"*.com", "anything.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.pattern+"_"+tc.domain, func(t *testing.T) {
			got := matchWildcard(tc.pattern, tc.domain)
			if got != tc.want {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.pattern, tc.domain, got, tc.want)
			}
		})
	}
}
