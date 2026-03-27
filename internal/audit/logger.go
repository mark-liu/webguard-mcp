package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is a single audit record written as one JSONL line.
type Entry struct {
	Timestamp   time.Time      `json:"timestamp"`
	URL         string         `json:"url"`
	Verdict     string         `json:"verdict"`
	Score       float64        `json:"score"`
	Matches     []MatchSummary `json:"matches,omitempty"`
	FetchTimeMS float64        `json:"fetch_time_ms"`
	ScanTimeMS  float64        `json:"scan_time_ms"`
	TotalTimeMS float64        `json:"total_time_ms"`
	StatusCode  int            `json:"status_code,omitempty"`
	Error       string         `json:"error,omitempty"`
}

// MatchSummary is a compact representation of a single pattern hit.
type MatchSummary struct {
	PatternID string `json:"pattern_id"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
}

// Logger writes JSONL audit entries to a file. It is safe for concurrent use.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	enabled bool
}

// New creates a new audit logger. If path is empty the DefaultPath is used.
// When enabled is false every write becomes a no-op; no file is opened.
func New(path string, enabled bool) (*Logger, error) {
	l := &Logger{enabled: enabled}
	if !enabled {
		return l, nil
	}

	if path == "" {
		path = DefaultPath()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	l.file = f
	return l, nil
}

// Log writes entry as a single JSON line. If the logger is disabled or was
// created without an open file the call is a silent no-op.
func (l *Logger) Log(entry Entry) {
	if !l.enabled || l.file == nil {
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return // best effort; don't crash the caller
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.file.Write(data)
}

// Close flushes and closes the underlying log file. It is safe to call on a
// disabled logger.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

// DefaultPath returns ~/.local/share/webguard-mcp/audit.jsonl.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "audit.jsonl"
	}
	return filepath.Join(home, ".local", "share", "webguard-mcp", "audit.jsonl")
}

// ReadEntries reads all audit entries from the JSONL file at path, filtered
// to entries at or after since. If since is zero, all entries are returned.
func ReadEntries(path string, since time.Time) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1MB line buffer

	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // skip malformed lines
		}
		if !since.IsZero() && entry.Timestamp.Before(since) {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}
