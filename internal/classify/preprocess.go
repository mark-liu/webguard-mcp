package classify

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/html"
	"golang.org/x/text/unicode/norm"
)

// PreprocessResult holds the output of the preprocessing pipeline.
type PreprocessResult struct {
	CleanText      string        `json:"clean_text"`
	RawText        string        `json:"-"` // pre-HTML-strip text for raw pattern scanning
	HTMLComments   []string      `json:"html_comments,omitempty"`
	DecodedBlobs   []EncodedBlob `json:"decoded_blobs,omitempty"`
	ZeroWidthCount int           `json:"zero_width_count"`
}

// htmlCommentRE extracts HTML comment bodies.
var htmlCommentRE = regexp.MustCompile(`<!--([\s\S]*?)-->`)

// zeroWidthChars is the set of zero-width Unicode characters to detect and strip.
var zeroWidthChars = map[rune]bool{
	'\u200B': true, // zero-width space
	'\u200C': true, // zero-width non-joiner
	'\u200D': true, // zero-width joiner
	'\uFEFF': true, // byte order mark / zero-width no-break space
}

// Preprocess runs an 8-step pipeline to normalise raw content into a form
// suitable for pattern matching:
//  1. Preserve raw text (pre-HTML-strip) for pattern scanning
//  2. Extract HTML comments
//  3. Strip HTML tags
//  4. Decode HTML entities
//  5. Detect and decode base64 blobs
//  6. URL-decode %XX sequences
//  7. Unicode NFC normalise
//  8. Detect, count, and strip zero-width characters
func Preprocess(raw string) PreprocessResult {
	var result PreprocessResult

	// Step 1: Preserve raw text before HTML stripping. Patterns like <<SYS>>
	// are destroyed by the HTML tokenizer (angle brackets parsed as tags), so
	// we keep the raw form for a separate scan pass.
	result.RawText = raw

	// Step 2: Extract HTML comments before stripping tags.
	commentMatches := htmlCommentRE.FindAllStringSubmatch(raw, -1)
	for _, m := range commentMatches {
		result.HTMLComments = append(result.HTMLComments, strings.TrimSpace(m[1]))
	}
	text := htmlCommentRE.ReplaceAllString(raw, " ")

	// Step 3: Strip HTML tags using the html tokenizer.
	text = stripHTMLTags(text)

	// Step 4: Decode HTML entities.
	text = html.UnescapeString(text)

	// Step 5: Detect and decode base64 blobs.
	result.DecodedBlobs = DetectBase64(text)

	// Step 6: URL-decode percent-encoded sequences.
	text = DecodeURLEncoded(text)

	// Step 7: Unicode NFC normalisation.
	text = norm.NFC.String(text)

	// Step 8: Detect, count, and strip zero-width characters.
	result.ZeroWidthCount = countZeroWidth(text)
	text = stripZeroWidth(text)

	result.CleanText = text
	return result
}

// stripHTMLTags uses the html tokenizer to extract text content, discarding
// all markup.
func stripHTMLTags(s string) string {
	tokenizer := html.NewTokenizer(strings.NewReader(s))
	var b strings.Builder

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return b.String()
		case html.TextToken:
			b.Write(tokenizer.Text())
		case html.StartTagToken, html.EndTagToken, html.SelfClosingTagToken:
			// Replace tags with a space to avoid words merging across tags.
			b.WriteByte(' ')
		}
	}
}

// countZeroWidth returns the number of zero-width characters in the string.
func countZeroWidth(s string) int {
	count := 0
	for _, r := range s {
		if zeroWidthChars[r] {
			count++
		}
	}
	return count
}

// stripZeroWidth removes all zero-width characters from the string.
func stripZeroWidth(s string) string {
	return strings.Map(func(r rune) rune {
		if zeroWidthChars[r] {
			return -1
		}
		// Also strip other potentially problematic invisible formatters that
		// aren't in the zero-width set but are non-printable controls.
		if r != '\n' && r != '\r' && r != '\t' && r != ' ' && unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, s)
}
