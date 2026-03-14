package classify

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// EncodedBlob represents a detected encoded segment within content, along
// with its decoded form and positional information.
type EncodedBlob struct {
	Encoded  string `json:"encoded"`
	Decoded  string `json:"decoded"`
	Offset   int    `json:"offset"`
	Length   int    `json:"length"`
	Encoding string `json:"encoding"`
}

// base64RE matches contiguous base64 character runs of at least 20 chars,
// optionally ending with padding.
var base64RE = regexp.MustCompile(`[A-Za-z0-9+/\-_]{20,}={0,3}`)

// DetectBase64 scans content for base64-encoded blobs and returns those that
// decode to valid UTF-8 text.
func DetectBase64(content string) []EncodedBlob {
	locs := base64RE.FindAllStringIndex(content, -1)
	var blobs []EncodedBlob

	for _, loc := range locs {
		raw := content[loc[0]:loc[1]]
		decoded, ok := DecodeBase64(raw)
		if !ok {
			continue
		}
		if !utf8.ValidString(decoded) {
			continue
		}
		// Skip blobs that decode to something too short to be meaningful.
		if len(decoded) < 4 {
			continue
		}
		blobs = append(blobs, EncodedBlob{
			Encoded:  raw,
			Decoded:  decoded,
			Offset:   loc[0],
			Length:   loc[1] - loc[0],
			Encoding: "base64",
		})
	}

	return blobs
}

// DecodeBase64 attempts standard base64 first, then URL-safe base64. Returns
// the decoded string and whether decoding succeeded.
func DecodeBase64(blob string) (string, bool) {
	// Try standard base64.
	if decoded, err := base64.StdEncoding.DecodeString(blob); err == nil {
		return string(decoded), true
	}
	// Try with no padding (RawStdEncoding).
	if decoded, err := base64.RawStdEncoding.DecodeString(blob); err == nil {
		return string(decoded), true
	}
	// Try URL-safe base64.
	if decoded, err := base64.URLEncoding.DecodeString(blob); err == nil {
		return string(decoded), true
	}
	// Try URL-safe without padding.
	if decoded, err := base64.RawURLEncoding.DecodeString(blob); err == nil {
		return string(decoded), true
	}

	return "", false
}

// DecodeURLEncoded decodes percent-encoded sequences (%XX) in content.
func DecodeURLEncoded(content string) string {
	decoded, err := url.QueryUnescape(content)
	if err != nil {
		return content
	}
	return decoded
}

// hexSeqRE matches \xNN hex escape sequences.
var hexSeqRE = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

// DecodeHexSequences replaces \xNN hex escape sequences with their byte values.
func DecodeHexSequences(content string) string {
	return hexSeqRE.ReplaceAllStringFunc(content, func(match string) string {
		hexStr := match[2:] // strip \x prefix
		val, err := strconv.ParseUint(hexStr, 16, 8)
		if err != nil {
			return match
		}
		return string(rune(val))
	})
}

// DecodeROT13 applies ROT13 substitution to ASCII letters.
func DecodeROT13(content string) string {
	var b strings.Builder
	b.Grow(len(content))

	for _, r := range content {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			b.WriteRune('A' + (r-'A'+13)%26)
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}
