package classify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExternalPattern is the YAML format for user-contributed patterns.
type ExternalPattern struct {
	ID       string `yaml:"id"`
	Category string `yaml:"category"`
	Severity string `yaml:"severity"`
	Type     string `yaml:"type"` // "literal" or "regex"
	Value    string `yaml:"value"`
}

// ExternalPatternFile is the top-level structure of a patterns YAML file.
type ExternalPatternFile struct {
	Patterns []ExternalPattern `yaml:"patterns"`
}

// LoadExternalPatterns reads all *.yaml and *.yml files from dir and returns
// the parsed patterns. Returns nil and no error if dir is empty or doesn't exist.
func LoadExternalPatterns(dir string) ([]Pattern, error) {
	if dir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read patterns dir: %w", err)
	}

	var patterns []Pattern
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}

		var file ExternalPatternFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}

		for _, ep := range file.Patterns {
			sev := parseSeverity(ep.Severity)
			typ := PatternLiteral
			if ep.Type == "regex" {
				typ = PatternRegex
			}
			patterns = append(patterns, Pattern{
				ID:       ep.ID,
				Category: ep.Category,
				Severity: sev,
				Type:     typ,
				Value:    ep.Value,
				Weight:   severityWeight(sev),
			})
		}
	}

	return patterns, nil
}

// parseSeverity converts a string severity to the Severity type.
func parseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityMedium
	}
}
