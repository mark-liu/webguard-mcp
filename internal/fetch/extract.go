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

// boilerplateElements are HTML elements stripped for context efficiency after
// security scanning is complete. These often contain navigation, site chrome,
// and footer content that adds no value for LLM reasoning.
var boilerplateElements = map[string]bool{
	"nav":    true,
	"header": true,
	"footer": true,
	"aside":  true,
}

// collapseNewlines matches three or more consecutive newlines.
var collapseNewlines = regexp.MustCompile(`\n{3,}`)

// Extract converts HTML content to clean markdown.
//
// It strips script, style, svg, noscript, and iframe elements before
// conversion, then collapses excessive whitespace.
func Extract(htmlContent []byte, contentType string) (string, error) {
	return extract(htmlContent, false)
}

// ExtractClean converts HTML to markdown with additional boilerplate stripping.
//
// Like Extract, but also removes nav, header, footer, and aside elements.
// Use this for the final output after security scanning is complete — the
// classifier should see full content via Extract, but the LLM gets clean
// content via ExtractClean.
func ExtractClean(htmlContent []byte, contentType string) (string, error) {
	return extract(htmlContent, true)
}

func extract(htmlContent []byte, stripBoilerplate bool) (string, error) {
	doc, err := html.Parse(bytes.NewReader(htmlContent))
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML: %w", err)
	}

	stripForbidden(doc)
	if stripBoilerplate {
		stripElements(doc, boilerplateElements)
	}

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
	stripElements(n, forbiddenElements)
}

// stripElements walks the HTML node tree and removes any element whose tag
// name is in the given set, along with all of its children.
func stripElements(n *html.Node, tags map[string]bool) {
	var next *html.Node
	for c := n.FirstChild; c != nil; c = next {
		next = c.NextSibling
		if c.Type == html.ElementNode && tags[c.Data] {
			n.RemoveChild(c)
			continue
		}
		stripElements(c, tags)
	}
}
