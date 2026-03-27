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

// ClassifyOptions holds optional parameters for the classification pipeline.
type ClassifyOptions struct {
	SuppressCategories map[string]bool // pattern categories to ignore
}

// Engine is the two-stage prompt injection classifier. It preprocesses
// content, runs fast pattern matching (Stage 1), then applies heuristic
// scoring (Stage 2) to produce a verdict.
type Engine struct {
	sensitivity Sensitivity
	threshold   float64
	patterns    *compiledPatterns
}

// NewEngine creates a classifier engine with the given sensitivity level
// using the built-in pattern set.
func NewEngine(sensitivity Sensitivity) *Engine {
	return NewEngineWithPatterns(sensitivity, nil)
}

// NewEngineWithPatterns creates a classifier engine that merges built-in
// patterns with additional external patterns.
func NewEngineWithPatterns(sensitivity Sensitivity, extra []Pattern) *Engine {
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

	defs := allPatterns()
	if len(extra) > 0 {
		defs = append(defs, extra...)
	}

	return &Engine{
		sensitivity: sensitivity,
		threshold:   threshold,
		patterns:    compilePatternsFrom(defs),
	}
}

// PatternCount returns the total number of compiled detection patterns.
func (e *Engine) PatternCount() int {
	return len(e.patterns.allDefinitions)
}

// Classify runs the full two-stage analysis pipeline on the provided content
// and returns a classification result. Equivalent to ClassifyWithOptions with
// empty options.
func (e *Engine) Classify(content string) Result {
	return e.ClassifyWithOptions(content, ClassifyOptions{})
}

// ClassifyWithOptions runs the two-stage pipeline with optional parameters
// such as category suppression.
//
// Flow:
//  1. Preprocess (HTML strip, decode, normalise)
//  2. Stage 1: fast pattern matching (Aho-Corasick + regex)
//  3. Filter suppressed categories
//  4. Early exit on zero matches (pass) or critical match (block)
//  5. Stage 2: heuristic scoring with density/clustering/proximity
//  6. Threshold comparison for final verdict
func (e *Engine) ClassifyWithOptions(content string, opts ClassifyOptions) Result {
	start := time.Now()

	// Step 1: Preprocess.
	pp := Preprocess(content)

	// Step 2: Stage 1 scanning (clean text + raw text + comments + decoded).
	matches := e.ScanStage1(pp.CleanText, pp.RawText, pp.HTMLComments, pp.DecodedBlobs)

	// Step 3: Filter suppressed categories.
	if len(opts.SuppressCategories) > 0 {
		matches = filterSuppressed(matches, opts.SuppressCategories)
	}

	elapsed := time.Since(start)

	// Step 4: Zero matches — clean content.
	if len(matches) == 0 {
		return Result{
			Verdict:  VerdictPass,
			Score:    0,
			Stage:    1,
			TimingMS: float64(elapsed.Microseconds()) / 1000.0,
		}
	}

	// Step 5: Any critical severity match triggers immediate block.
	for _, m := range matches {
		if m.Severity == SeverityCritical {
			elapsed = time.Since(start)
			return Result{
				Verdict:  VerdictBlock,
				Score:    e.ScoreStage2(matches, len(pp.CleanText), len(pp.DecodedBlobs) > 0, pp.ZeroWidthCount),
				Matches:  matches,
				Stage:    1,
				TimingMS: float64(elapsed.Microseconds()) / 1000.0,
			}
		}
	}

	// Step 6: Stage 2 scoring.
	hasEncoded := len(pp.DecodedBlobs) > 0
	score := e.ScoreStage2(matches, len(pp.CleanText), hasEncoded, pp.ZeroWidthCount)
	elapsed = time.Since(start)

	// Step 7: Threshold verdict.
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

// filterSuppressed removes matches whose category is in the suppress set.
func filterSuppressed(matches []Match, suppress map[string]bool) []Match {
	var filtered []Match
	for _, m := range matches {
		if !suppress[m.Category] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}
