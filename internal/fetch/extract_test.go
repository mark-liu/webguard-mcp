package fetch

import (
	"strings"
	"testing"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name        string
		html        string
		contentType string
		wantErr     bool
		check       func(t *testing.T, result string)
	}{
		{
			name: "simple HTML converts to markdown",
			html: `<html><body>
				<h1>Title</h1>
				<p>A paragraph with a <a href="https://example.com">link</a>.</p>
				<ul><li>item one</li><li>item two</li></ul>
			</body></html>`,
			contentType: "text/html",
			check: func(t *testing.T, result string) {
				if !strings.Contains(result, "# Title") {
					t.Error("expected markdown heading '# Title'")
				}
				if !strings.Contains(result, "[link](https://example.com)") {
					t.Error("expected markdown link '[link](https://example.com)'")
				}
				if !strings.Contains(result, "item one") {
					t.Error("expected list item 'item one'")
				}
				if !strings.Contains(result, "item two") {
					t.Error("expected list item 'item two'")
				}
			},
		},
		{
			name: "script tags stripped",
			html: `<html><body>
				<p>safe content</p>
				<script>alert('xss')</script>
			</body></html>`,
			contentType: "text/html",
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "alert") {
					t.Error("script content should be stripped")
				}
				if !strings.Contains(result, "safe content") {
					t.Error("normal content should be preserved")
				}
			},
		},
		{
			name: "style tags stripped",
			html: `<html><body>
				<style>body { color: red; }</style>
				<p>visible text</p>
			</body></html>`,
			contentType: "text/html",
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "color: red") {
					t.Error("style content should be stripped")
				}
				if !strings.Contains(result, "visible text") {
					t.Error("normal content should be preserved")
				}
			},
		},
		{
			name: "iframe stripped",
			html: `<html><body>
				<iframe src="https://evil.com"></iframe>
				<p>kept</p>
			</body></html>`,
			contentType: "text/html",
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "iframe") {
					t.Error("iframe element should be stripped")
				}
				if strings.Contains(result, "evil.com") {
					t.Error("iframe src should be stripped")
				}
				if !strings.Contains(result, "kept") {
					t.Error("normal content should be preserved")
				}
			},
		},
		{
			name: "normal content preserved",
			html: `<html><body>
				<h2>Section</h2>
				<p>Paragraph text here.</p>
			</body></html>`,
			contentType: "text/html",
			check: func(t *testing.T, result string) {
				if !strings.Contains(result, "Section") {
					t.Error("heading content should be preserved")
				}
				if !strings.Contains(result, "Paragraph text here.") {
					t.Error("paragraph content should be preserved")
				}
			},
		},
		{
			name:        "empty HTML",
			html:        "",
			contentType: "text/html",
			wantErr:     false,
			check: func(t *testing.T, result string) {
				if result != "" {
					t.Errorf("expected empty result for empty HTML, got %q", result)
				}
			},
		},
		{
			name:        "excessive newlines collapsed",
			html:        "<html><body><p>one</p>\n\n\n\n\n<p>two</p></body></html>",
			contentType: "text/html",
			check: func(t *testing.T, result string) {
				if strings.Contains(result, "\n\n\n") {
					t.Error("three or more consecutive newlines should be collapsed to two")
				}
				if !strings.Contains(result, "one") || !strings.Contains(result, "two") {
					t.Error("content should be preserved")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Extract([]byte(tc.html), tc.contentType)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Extract() = %q, nil; want error", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract() unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, result)
			}
		})
	}
}
