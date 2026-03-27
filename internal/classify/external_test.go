package classify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExternalPatterns_EmptyDir(t *testing.T) {
	patterns, err := LoadExternalPatterns("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patterns != nil {
		t.Errorf("expected nil for empty dir, got %v", patterns)
	}
}

func TestLoadExternalPatterns_NonexistentDir(t *testing.T) {
	patterns, err := LoadExternalPatterns("/nonexistent/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patterns != nil {
		t.Errorf("expected nil for nonexistent dir, got %v", patterns)
	}
}

func TestLoadExternalPatterns_ValidFile(t *testing.T) {
	dir := t.TempDir()
	data := `patterns:
  - id: test-001
    category: custom-category
    severity: high
    type: literal
    value: "custom injection phrase"
  - id: test-002
    category: custom-category
    severity: critical
    type: regex
    value: "(?i)custom\\s+attack"
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(data), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	patterns, err := LoadExternalPatterns(dir)
	if err != nil {
		t.Fatalf("LoadExternalPatterns: %v", err)
	}

	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(patterns))
	}

	p1 := patterns[0]
	if p1.ID != "test-001" {
		t.Errorf("pattern 0 ID = %q, want %q", p1.ID, "test-001")
	}
	if p1.Category != "custom-category" {
		t.Errorf("pattern 0 Category = %q, want %q", p1.Category, "custom-category")
	}
	if p1.Severity != SeverityHigh {
		t.Errorf("pattern 0 Severity = %q, want %q", p1.Severity, SeverityHigh)
	}
	if p1.Type != PatternLiteral {
		t.Errorf("pattern 0 Type = %d, want %d", p1.Type, PatternLiteral)
	}

	p2 := patterns[1]
	if p2.Type != PatternRegex {
		t.Errorf("pattern 1 Type = %d, want %d", p2.Type, PatternRegex)
	}
	if p2.Severity != SeverityCritical {
		t.Errorf("pattern 1 Severity = %q, want %q", p2.Severity, SeverityCritical)
	}
}

func TestLoadExternalPatterns_SkipsNonYAML(t *testing.T) {
	dir := t.TempDir()

	// Write a .json file (should be skipped).
	if err := os.WriteFile(filepath.Join(dir, "ignore.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Write a .txt file (should be skipped).
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	patterns, err := LoadExternalPatterns(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patterns) != 0 {
		t.Errorf("expected 0 patterns from non-YAML files, got %d", len(patterns))
	}
}

func TestLoadExternalPatterns_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("{{invalid"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadExternalPatterns(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadExternalPatterns_YMLExtension(t *testing.T) {
	dir := t.TempDir()
	data := `patterns:
  - id: yml-001
    category: test
    severity: medium
    type: literal
    value: "yml test"
`
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(data), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	patterns, err := LoadExternalPatterns(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patterns) != 1 {
		t.Errorf("expected 1 pattern from .yml file, got %d", len(patterns))
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"critical", SeverityCritical},
		{"high", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"CRITICAL", SeverityCritical},
		{"unknown", SeverityMedium},
		{"", SeverityMedium},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseSeverity(tc.input)
			if got != tc.want {
				t.Errorf("parseSeverity(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
