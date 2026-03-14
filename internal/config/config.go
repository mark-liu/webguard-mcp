package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DomainConfig holds per-domain overrides.
type DomainConfig struct {
	Sensitivity string `yaml:"sensitivity"`
}

// AuditConfig controls the audit logger.
type AuditConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// Config holds the top-level webguard-mcp configuration.
type Config struct {
	Sensitivity string                  `yaml:"sensitivity"`
	MaxBodySize int64                   `yaml:"max_body_size"`
	Timeout     Duration                `yaml:"request_timeout"`
	Domains     map[string]DomainConfig `yaml:"domains"`
	Allowlist   []string                `yaml:"allowlist"`
	Blocklist   []string                `yaml:"blocklist"`
	Audit       AuditConfig             `yaml:"audit"`
}

// Duration wraps time.Duration for YAML unmarshalling from human-readable
// strings such as "15s" or "2m30s".
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses a duration string (e.g. "15s") into Duration.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// MarshalYAML serialises Duration back to a string.
func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Sensitivity: "medium",
		MaxBodySize: 5 << 20, // 5 MiB
		Timeout:     Duration{15 * time.Second},
		Domains:     nil,
		Allowlist:   nil,
		Blocklist:   nil,
		Audit: AuditConfig{
			Enabled: true,
			Path:    "", // empty = auto-resolved at runtime
		},
	}
}

// DefaultPath returns ~/.config/webguard-mcp/config.yaml.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(home, ".config", "webguard-mcp", "config.yaml")
}

// Load reads config from a YAML file at path. If the file does not exist
// the returned Config contains sensible defaults and err is nil.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// SensitivityForDomain returns the sensitivity level for domain, checking
// domain-specific overrides first (including wildcard entries like
// *.example.com). Falls back to the global sensitivity.
func (c *Config) SensitivityForDomain(domain string) string {
	if c.Domains == nil {
		return c.Sensitivity
	}

	domain = strings.ToLower(domain)

	// Exact match first.
	if dc, ok := c.Domains[domain]; ok && dc.Sensitivity != "" {
		return dc.Sensitivity
	}

	// Wildcard match: *.example.com matches sub.example.com but not
	// example.com itself. Walk through all domain configs because the
	// map is typically small.
	for pattern, dc := range c.Domains {
		if matchWildcard(pattern, domain) && dc.Sensitivity != "" {
			return dc.Sensitivity
		}
	}

	return c.Sensitivity
}

// IsAllowed reports whether domain appears in the allowlist (supports
// wildcard entries). An empty allowlist means everything is allowed.
func (c *Config) IsAllowed(domain string) bool {
	if len(c.Allowlist) == 0 {
		return true
	}
	return matchAny(c.Allowlist, domain)
}

// IsBlocked reports whether domain appears in the blocklist (supports
// wildcard entries). An empty blocklist means nothing is blocked.
func (c *Config) IsBlocked(domain string) bool {
	if len(c.Blocklist) == 0 {
		return false
	}
	return matchAny(c.Blocklist, domain)
}

// matchAny checks domain against a list of patterns, each of which may
// be an exact domain or a wildcard like *.example.com.
func matchAny(patterns []string, domain string) bool {
	domain = strings.ToLower(domain)
	for _, p := range patterns {
		if matchWildcard(p, domain) {
			return true
		}
		if strings.EqualFold(p, domain) {
			return true
		}
	}
	return false
}

// matchWildcard checks whether pattern (e.g. "*.example.com") matches
// domain. The wildcard prefix matches any single subdomain level or
// deeper, but does not match the bare parent domain.
func matchWildcard(pattern, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := strings.ToLower(pattern[1:]) // ".example.com"
	return strings.HasSuffix(domain, suffix) && domain != suffix[1:]
}
