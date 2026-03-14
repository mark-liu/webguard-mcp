package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNew_Disabled(t *testing.T) {
	l, err := New("", false)
	if err != nil {
		t.Fatalf("New(disabled): %v", err)
	}
	defer l.Close()

	if l.file != nil {
		t.Error("disabled logger should not open a file")
	}
}

func TestNew_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deep", "audit.jsonl")

	l, err := New(path, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("parent dirs not created: %v", err)
	}
}

func TestLog_WritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Now().Truncate(time.Millisecond)
	entry := Entry{
		Timestamp:   now,
		URL:         "https://example.com",
		Verdict:     "pass",
		Score:       0.1,
		FetchTimeMS: 42.5,
		ScanTimeMS:  3.2,
		TotalTimeMS: 45.7,
		StatusCode:  200,
		Matches: []MatchSummary{
			{PatternID: "xss-001", Category: "xss", Severity: "high"},
		},
	}
	l.Log(entry)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("no lines in audit file")
	}

	var got Entry
	if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", got.URL, "https://example.com")
	}
	if got.Verdict != "pass" {
		t.Errorf("Verdict = %q, want %q", got.Verdict, "pass")
	}
	if len(got.Matches) != 1 {
		t.Fatalf("Matches len = %d, want 1", len(got.Matches))
	}
	if got.Matches[0].PatternID != "xss-001" {
		t.Errorf("PatternID = %q, want %q", got.Matches[0].PatternID, "xss-001")
	}
}

func TestLog_DisabledIsNoop(t *testing.T) {
	l, err := New("", false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Should not panic or error.
	l.Log(Entry{URL: "https://example.com"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestLog_MultipleEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 5; i++ {
		l.Log(Entry{URL: "https://example.com", Score: float64(i)})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("line %d: %v", count, err)
		}
		count++
	}
	if count != 5 {
		t.Errorf("got %d lines, want 5", count)
	}
}

func TestLog_ConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			l.Log(Entry{URL: "https://example.com", Score: float64(idx)})
		}(i)
	}
	wg.Wait()

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("line %d: unmarshal: %v", count, err)
		}
		count++
	}
	if count != n {
		t.Errorf("got %d lines, want %d", count, n)
	}
}

func TestDefaultPath(t *testing.T) {
	p := DefaultPath()
	if p == "" {
		t.Fatal("DefaultPath returned empty string")
	}
	if filepath.Base(p) != "audit.jsonl" {
		t.Errorf("DefaultPath base = %q, want %q", filepath.Base(p), "audit.jsonl")
	}
}

func TestLog_OmitsEmptyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(path, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	l.Log(Entry{
		URL:     "https://example.com",
		Verdict: "pass",
	})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// status_code is omitempty, should not appear when zero.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["status_code"]; ok {
		t.Error("status_code should be omitted when zero")
	}
	if _, ok := raw["matches"]; ok {
		t.Error("matches should be omitted when nil")
	}
	if _, ok := raw["error"]; ok {
		t.Error("error should be omitted when empty")
	}
}
