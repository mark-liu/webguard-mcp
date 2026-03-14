package fetch

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	htmltomarkdown "github.com/JohannesKaufmann/html-to-markdown/v2"
	"golang.org/x/net/html"
)

// forbiddenElements are HTML elements that are stripped entirely (including
// all nested content) before markdown conversion.
var forbiddenElements = map[string]bool{
	"script":   true,
	"style":    true,
	"svg":      true,
	"noscript": true,
	"iframe":   true,
}

// collapseNewlines matches three or more consecutive newlines.
var collapseNewlines = regexp.MustCompile(`\n{3,}`)

// Extract converts HTML content to clean markdown.
//
// It strips script, style, svg, noscript, and iframe elements before
// conversion, then collapses excessive whitespace.
func Extract(htmlContent []byte, contentType string) (string, error) {
	doc, err := html.Parse(bytes.NewReader(htmlContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML: %w", err)
	}

	stripForbidden(doc)

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return "", fmt.Errorf("failed to re-serialize HTML: %w", err)
	}

	md, err := htmltomarkdown.ConvertString(buf.String())
	if err != nil {
		return "", fmt.Errorf("failed to convert HTML to markdown: %w", err)
	}

	md = collapseNewlines.ReplaceAllString(md, "\n\n")
	md = strings.TrimSpace(md)

	return md, nil
}

// stripForbidden walks the HTML node tree and removes any element whose tag
// name is in the forbiddenElements set, along with all of its children.
func stripForbidden(n *html.Node) {
	var next *html.Node
	for c := n.FirstChild; c != nil; c = next {
		next = c.NextSibling
		if c.Type == html.ElementNode && forbiddenElements[c.Data] {
			n.RemoveChild(c)
			continue
		}
		stripForbidden(c)
	}
}
