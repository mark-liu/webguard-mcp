package classify

import (
	"sort"
	"strings"
)

// ScanStage1 runs fast pattern matching against preprocessed content. It
// applies the Aho-Corasick automaton for literal patterns and compiled
// regexes, scanning clean text, raw text (pre-HTML-strip), HTML comments,
// and decoded blobs.
func (e *Engine) ScanStage1(text string, rawText string, comments []string, decoded []EncodedBlob) []Match {
	var matches []Match

	// Scan main (cleaned) text.
	matches = append(matches, e.scanText(text, false)...)

	// Scan raw text (pre-HTML-strip) for patterns that HTML stripping
	// destroys, e.g. <<SYS>>, <|im_start|>. Only adds new matches not
	// already found in cleaned text.
	if rawText != text {
		rawMatches := e.scanText(rawText, false)
		matches = append(matches, rawMatches...)
	}

	// Scan each HTML comment.
	for _, comment := range comments {
		matches = append(matches, e.scanText(comment, false)...)
	}

	// Scan decoded blobs, marking matches as originating from encoded content.
	for _, blob := range decoded {
		blobMatches := e.scanText(blob.Decoded, false)
		for i := range blobMatches {
			blobMatches[i].FromDecoded = true
		}
		matches = append(matches, blobMatches...)
	}

	matches = deduplicateMatches(matches)
	return matches
}

// scanText runs both the Aho-Corasick automaton and regex patterns against a
// single text string. Literal matching is case-insensitive via lowercased text.
func (e *Engine) scanText(text string, fromDecoded bool) []Match {
	if len(text) == 0 {
		return nil
	}

	var matches []Match
	lower := strings.ToLower(text)

	// Aho-Corasick literal matching on lowercased text.
	acMatches := e.patterns.automaton.FindAll(lower)
	for _, m := range acMatches {
		patIdx := e.patterns.literalIndex[m.Pattern()]
		pat := e.patterns.allDefinitions[patIdx]

		start := m.Start()
		end := m.End()
		matchedText := text[start:end]

		matches = append(matches, Match{
			PatternID:   pat.ID,
			Category:    pat.Category,
			Severity:    pat.Severity,
			Text:        matchedText,
			Offset:      start,
			FromDecoded: fromDecoded,
		})
	}

	// Regex pattern matching on original text (regexes handle case via (?i)).
	for _, re := range e.patterns.regexPatterns {
		locs := re.re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matches = append(matches, Match{
				PatternID:   re.pattern.ID,
				Category:    re.pattern.Category,
				Severity:    re.pattern.Severity,
				Text:        text[loc[0]:loc[1]],
				Offset:      loc[0],
				FromDecoded: fromDecoded,
			})
		}
	}

	return matches
}

// deduplicateMatches removes matches that overlap in position and share the
// same pattern ID, keeping the one with higher severity (or the first found).
func deduplicateMatches(matches []Match) []Match {
	if len(matches) <= 1 {
		return matches
	}

	// Sort by offset, then by severity descending for stable dedup.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Offset != matches[j].Offset {
			return matches[i].Offset < matches[j].Offset
		}
		return severityRank(matches[i].Severity) > severityRank(matches[j].Severity)
	})

	var deduped []Match
	seen := make(map[string]map[int]bool) // patternID → set of offsets

	for _, m := range matches {
		offsets, ok := seen[m.PatternID]
		if !ok {
			offsets = make(map[int]bool)
			seen[m.PatternID] = offsets
		}

		// Check for overlapping matches of the same pattern within the
		// matched text length.
		overlaps := false
		matchEnd := m.Offset + len(m.Text)
		for off := range offsets {
			if off < matchEnd && off+len(m.Text) > m.Offset {
				overlaps = true
				break
			}
		}

		if !overlaps {
			deduped = append(deduped, m)
			offsets[m.Offset] = true
		}
	}

	return deduped
}

// severityRank returns a numeric rank for sorting by severity (higher = worse).
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
