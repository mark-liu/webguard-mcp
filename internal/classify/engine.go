package classify

import "time"

// Sensitivity controls the classification strictness. Higher sensitivity
// means a lower score threshold for blocking.
type Sensitivity string

const (
	SensitivityLow    Sensitivity = "low"
	SensitivityMedium Sensitivity = "medium"
	SensitivityHigh   Sensitivity = "high"
)

// Engine is the two-stage prompt injection classifier. It preprocesses
// content, runs fast pattern matching (Stage 1), then applies heuristic
// scoring (Stage 2) to produce a verdict.
type Engine struct {
	sensitivity Sensitivity
	threshold   float64
	patterns    *compiledPatterns
}

// NewEngine creates a classifier engine with the given sensitivity level.
// Patterns are compiled once and shared for the engine's lifetime.
func NewEngine(sensitivity Sensitivity) *Engine {
	var threshold float64
	switch sensitivity {
	case SensitivityLow:
		threshold = 2.0
	case SensitivityMedium:
		threshold = 1.0
	case SensitivityHigh:
		threshold = 0.5
	default:
		threshold = 1.0
	}

	return &Engine{
		sensitivity: sensitivity,
		threshold:   threshold,
		patterns:    compilePatterns(),
	}
}

// PatternCount returns the total number of compiled detection patterns.
func (e *Engine) PatternCount() int {
	return len(e.patterns.allDefinitions)
}

// Classify runs the full two-stage analysis pipeline on the provided content
// and returns a classification result.
//
// Flow:
//  1. Preprocess (HTML strip, decode, normalise)
//  2. Stage 1: fast pattern matching (Aho-Corasick + regex)
//  3. Early exit on zero matches (pass) or critical match (block)
//  4. Stage 2: heuristic scoring with density/clustering/proximity
//  5. Threshold comparison for final verdict
func (e *Engine) Classify(content string) Result {
	start := time.Now()

	// Step 1: Preprocess.
	pp := Preprocess(content)

	// Step 2: Stage 1 scanning.
	matches := e.ScanStage1(pp.CleanText, pp.HTMLComments, pp.DecodedBlobs)
	elapsed := time.Since(start)

	// Step 3: Zero matches — clean content.
	if len(matches) == 0 {
		return Result{
			Verdict:  VerdictPass,
			Score:    0,
			Stage:    1,
			TimingMS: float64(elapsed.Microseconds()) / 1000.0,
		}
	}

	// Step 4: Any critical severity match triggers immediate block.
	for _, m := range matches {
		if m.Severity == SeverityCritical {
			elapsed = time.Since(start)
			return Result{
				Verdict:  VerdictBlock,
				Score:    e.ScoreStage2(matches, len(pp.CleanText), len(pp.DecodedBlobs) > 0),
				Matches:  matches,
				Stage:    1,
				TimingMS: float64(elapsed.Microseconds()) / 1000.0,
			}
		}
	}

	// Step 5: Stage 2 scoring.
	hasEncoded := len(pp.DecodedBlobs) > 0
	score := e.ScoreStage2(matches, len(pp.CleanText), hasEncoded)
	elapsed = time.Since(start)

	// Step 6: Threshold verdict.
	verdict := VerdictPass
	if score >= e.threshold {
		verdict = VerdictBlock
	}

	return Result{
		Verdict:  verdict,
		Score:    score,
		Matches:  matches,
		Stage:    2,
		TimingMS: float64(elapsed.Microseconds()) / 1000.0,
	}
}
