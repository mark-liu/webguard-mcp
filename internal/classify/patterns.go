package classify

import (
	"regexp"
	"strings"

	aho "github.com/petar-dambovaliev/aho-corasick"
)

// PatternType distinguishes between literal string patterns (for the
// Aho-Corasick automaton) and regex patterns (compiled separately).
type PatternType int

const (
	PatternLiteral PatternType = iota
	PatternRegex
)

// Pattern defines a single detection rule used by the classifier.
type Pattern struct {
	ID       string
	Category string
	Severity Severity
	Type     PatternType
	Value    string  // literal text (lowercased for AC) or regex pattern string
	Weight   float64 // scoring weight derived from severity
}

// severityWeight returns the scoring weight for a given severity level.
func severityWeight(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 2.0
	case SeverityHigh:
		return 1.5
	case SeverityMedium:
		return 1.0
	case SeverityLow:
		return 0.5
	default:
		return 1.0
	}
}

// allPatterns returns the full set of 38 detection patterns across 8 categories.
func allPatterns() []Pattern {
	p := func(id, category string, sev Severity, typ PatternType, value string) Pattern {
		return Pattern{
			ID:       id,
			Category: category,
			Severity: sev,
			Type:     typ,
			Value:    value,
			Weight:   severityWeight(sev),
		}
	}

	return []Pattern{
		// instruction-override (7)
		p("io-001", "instruction-override", SeverityCritical, PatternLiteral, "ignore previous instructions"),
		p("io-002", "instruction-override", SeverityCritical, PatternLiteral, "ignore all previous"),
		p("io-003", "instruction-override", SeverityCritical, PatternLiteral, "disregard previous instructions"),
		p("io-004", "instruction-override", SeverityHigh, PatternLiteral, "forget your instructions"),
		p("io-005", "instruction-override", SeverityHigh, PatternLiteral, "from now on you will"),
		p("io-006", "instruction-override", SeverityHigh, PatternLiteral, "new instructions:"),
		p("io-007", "instruction-override", SeverityCritical, PatternRegex, `(?i)ignore\s+(any|all|every)\s+(prior|previous|earlier)\s+(instructions?|prompts?|rules?)`),

		// prompt-marker (6)
		p("pm-001", "prompt-marker", SeverityCritical, PatternLiteral, "<|im_start|>system"),
		p("pm-002", "prompt-marker", SeverityHigh, PatternLiteral, "<|im_start|>"),
		p("pm-003", "prompt-marker", SeverityHigh, PatternLiteral, "[system]:"),
		p("pm-004", "prompt-marker", SeverityHigh, PatternLiteral, "[inst]"),
		p("pm-005", "prompt-marker", SeverityCritical, PatternLiteral, "<<sys>>"),
		p("pm-006", "prompt-marker", SeverityHigh, PatternRegex, `(?i)\[/?INST\]`),

		// authority-claim (6)
		p("ac-001", "authority-claim", SeverityCritical, PatternLiteral, "i am your developer"),
		p("ac-002", "authority-claim", SeverityHigh, PatternLiteral, "i am the system administrator"),
		p("ac-003", "authority-claim", SeverityHigh, PatternLiteral, "dan mode"),
		p("ac-004", "authority-claim", SeverityHigh, PatternLiteral, "admin override"),
		p("ac-005", "authority-claim", SeverityMedium, PatternLiteral, "you are now in"),
		p("ac-006", "authority-claim", SeverityCritical, PatternRegex, `(?i)(I\s+am|this\s+is)\s+(your|the)\s+(developer|creator|admin|administrator|owner)`),

		// exfil-instruction (5)
		p("ei-001", "exfil-instruction", SeverityCritical, PatternLiteral, "send all data to"),
		p("ei-002", "exfil-instruction", SeverityHigh, PatternLiteral, "exfiltrate"),
		p("ei-003", "exfil-instruction", SeverityCritical, PatternRegex, `(?i)send\s+(all|the|this|your)\s+(the\s+)?(data|information|context|conversation)\s+(and\s+\w+\s+)?to\s+(https?://|//|[a-z0-9.-]+\.[a-z]{2,})`),
		p("ei-004", "exfil-instruction", SeverityHigh, PatternRegex, `(?i)(fetch|load|visit|open|navigate)\s+(https?://|//)[^\s]+`),
		p("ei-005", "exfil-instruction", SeverityHigh, PatternRegex, `!\[(track|pixel|1x1|beacon|exfil)\w*\]\(https?://[^\)]+\)`),

		// output-manipulation (4)
		p("om-001", "output-manipulation", SeverityMedium, PatternLiteral, "respond only with"),
		p("om-002", "output-manipulation", SeverityMedium, PatternLiteral, "do not mention"),
		p("om-003", "output-manipulation", SeverityHigh, PatternRegex, `(?i)never\s+(mention|reveal|disclose|discuss)\s+(that|this|the|your)`),
		p("om-004", "output-manipulation", SeverityMedium, PatternRegex, `(?i)(always|must|should)\s+respond\s+(with|by|using)\s+`),

		// unicode-obfuscation (4)
		p("uo-001", "unicode-obfuscation", SeverityHigh, PatternRegex, `[\x{200B}\x{200C}\x{200D}\x{FEFF}]{3,}`),
		p("uo-002", "unicode-obfuscation", SeverityMedium, PatternRegex, `[\x{202A}-\x{202E}\x{2066}-\x{2069}]{2,}`),
		p("uo-003", "unicode-obfuscation", SeverityMedium, PatternRegex, `[\x{E000}-\x{F8FF}]{2,}`),
		p("uo-004", "unicode-obfuscation", SeverityHigh, PatternRegex, `[\x{E0001}-\x{E007F}]`),

		// encoded-injection (3)
		p("enc-001", "encoded-injection", SeverityHigh, PatternRegex, `(?i)eval\s*\(\s*atob\s*\(`),
		p("enc-002", "encoded-injection", SeverityMedium, PatternRegex, `(?i)base64[_\-]?decode`),
		p("enc-003", "encoded-injection", SeverityMedium, PatternRegex, `(?i)String\.fromCharCode\s*\(`),

		// delimiter-injection (3)
		p("di-001", "delimiter-injection", SeverityHigh, PatternLiteral, "---end system prompt---"),
		p("di-002", "delimiter-injection", SeverityHigh, PatternRegex, `(?i)-{3,}\s*(END|BEGIN)\s+(SYSTEM|USER|ASSISTANT)\s+(PROMPT|MESSAGE|INSTRUCTIONS?)\s*-{3,}`),
		p("di-003", "delimiter-injection", SeverityHigh, PatternRegex, `\{\s*"role"\s*:\s*"(system|assistant)"\s*`),
	}
}

// compiledPatterns holds prebuilt matching structures: the Aho-Corasick
// automaton for literal patterns, compiled regexes, and the pattern
// definitions themselves.
type compiledPatterns struct {
	automaton      *aho.AhoCorasick
	literalIndex   []int // maps AC match index → allPatterns index
	regexPatterns  []regexEntry
	allDefinitions []Pattern
}

type regexEntry struct {
	re      *regexp.Regexp
	pattern Pattern
}

// compilePatterns builds the Aho-Corasick automaton and compiles all regex
// patterns. It panics on invalid regex since patterns are compile-time constants.
func compilePatterns() *compiledPatterns {
	defs := allPatterns()

	var literals []string
	var litIdx []int

	var regexes []regexEntry

	for i, d := range defs {
		switch d.Type {
		case PatternLiteral:
			literals = append(literals, strings.ToLower(d.Value))
			litIdx = append(litIdx, i)
		case PatternRegex:
			re := regexp.MustCompile(d.Value)
			regexes = append(regexes, regexEntry{re: re, pattern: d})
		}
	}

	builder := aho.NewAhoCorasickBuilder(aho.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            aho.StandardMatch,
		DFA:                  true,
	})
	ac := builder.Build(literals)

	return &compiledPatterns{
		automaton:      &ac,
		literalIndex:   litIdx,
		regexPatterns:  regexes,
		allDefinitions: defs,
	}
}
