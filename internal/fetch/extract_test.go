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

func TestExtractClean(t *testing.T) {
	html := `<html><body>
		<nav><a href="/">Home</a><a href="/about">About</a></nav>
		<header><div class="logo">Site Logo</div></header>
		<main>
			<article>
				<h1>Article Title</h1>
				<p>This is the main content.</p>
			</article>
		</main>
		<aside><h3>Related Posts</h3><ul><li>Post 1</li></ul></aside>
		<footer><p>Copyright 2026</p></footer>
	</body></html>`

	// Extract (full) should include nav, header, footer, aside content.
	full, err := Extract([]byte(html), "text/html")
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	// ExtractClean should strip nav, header, footer, aside.
	clean, err := ExtractClean([]byte(html), "text/html")
	if err != nil {
		t.Fatalf("ExtractClean() error: %v", err)
	}

	// Full should contain boilerplate content.
	if !strings.Contains(full, "Home") {
		t.Error("Extract() should contain nav link 'Home'")
	}
	if !strings.Contains(full, "Site Logo") {
		t.Error("Extract() should contain header 'Site Logo'")
	}
	if !strings.Contains(full, "Copyright") {
		t.Error("Extract() should contain footer 'Copyright'")
	}
	if !strings.Contains(full, "Related Posts") {
		t.Error("Extract() should contain aside 'Related Posts'")
	}

	// Clean should NOT contain boilerplate.
	if strings.Contains(clean, "Home") {
		t.Error("ExtractClean() should not contain nav link 'Home'")
	}
	if strings.Contains(clean, "Site Logo") {
		t.Error("ExtractClean() should not contain header 'Site Logo'")
	}
	if strings.Contains(clean, "Copyright") {
		t.Error("ExtractClean() should not contain footer 'Copyright'")
	}
	if strings.Contains(clean, "Related Posts") {
		t.Error("ExtractClean() should not contain aside 'Related Posts'")
	}

	// Clean MUST contain main content.
	if !strings.Contains(clean, "Article Title") {
		t.Error("ExtractClean() must preserve 'Article Title'")
	}
	if !strings.Contains(clean, "main content") {
		t.Error("ExtractClean() must preserve 'main content'")
	}

	// Clean should be shorter than full.
	if len(clean) >= len(full) {
		t.Errorf("ExtractClean() (%d chars) should be shorter than Extract() (%d chars)", len(clean), len(full))
	}
}
