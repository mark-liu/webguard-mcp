package classify

// Verdict represents the classification outcome for scanned content.
type Verdict string

const (
	VerdictPass  Verdict = "pass"
	VerdictBlock Verdict = "block"
	VerdictWarn  Verdict = "warn"
)

// Severity indicates the threat level of a matched pattern.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Match represents a single pattern hit found during content scanning.
type Match struct {
	PatternID   string   `json:"pattern_id"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Text        string   `json:"matched_text"`
	Offset      int      `json:"offset"`
	FromDecoded bool     `json:"from_decoded,omitempty"`
}

// Result holds the full classification output including verdict, score, and
// any pattern matches found during the two-stage analysis pipeline.
type Result struct {
	Verdict  Verdict `json:"verdict"`
	Score    float64 `json:"score"`
	Matches  []Match `json:"matches,omitempty"`
	Stage    int     `json:"stage"`
	TimingMS float64 `json:"timing_ms"`
}
