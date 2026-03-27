package fetch

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultMaxBodySize = 5 * 1024 * 1024 // 5 MB
	defaultTimeout     = 15 * time.Second
	maxRedirects       = 5
	userAgent          = "webguard-mcp/0.1.0"
)

// FetchOptions controls HTTP fetch behaviour.
type FetchOptions struct {
	MaxBodySize int64
	Timeout     time.Duration
	Headers     map[string]string
}

// FetchResult holds the response from a successful fetch.
type FetchResult struct {
	StatusCode    int
	ContentType   string
	Body          []byte
	FinalURL      string
	RedirectCount int
}

// DefaultOptions returns sensible defaults for fetching.
func DefaultOptions() FetchOptions {
	return FetchOptions{
		MaxBodySize: defaultMaxBodySize,
		Timeout:     defaultTimeout,
	}
}

// Fetch retrieves content from a URL with full SSRF protection.
//
// The workflow is:
//  1. Validate the URL (scheme, authority, encoding, octal).
//  2. DNS-resolve the hostname and validate every returned IP.
//  3. Connect via a pinned-IP dialer so the TCP connection goes
//     to the validated IP, not a potentially different DNS result.
//  4. On each redirect, re-validate the new target URL and IP.
//  5. Cap the response body at MaxBodySize.
func Fetch(ctx context.Context, rawURL string, opts FetchOptions) (*FetchResult, error) {
	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = defaultMaxBodySize
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}

	// --- Phase 1: validate the initial URL and resolve DNS ---
	validatedURL, err := ValidateURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}

	pinnedIP, err := ResolveAndValidate(validatedURL.Hostname())
	if err != nil {
		return nil, fmt.Errorf("DNS validation failed: %w", err)
	}

	// --- Phase 2: build a pinned-dialer HTTP client ---
	result := &FetchResult{}

	// pinnedDialer connects to the resolved IP while keeping the
	// original Host header intact for TLS SNI / virtual hosting.
	pinnedDialer := &net.Dialer{Timeout: opts.Timeout}

	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("bad address %q: %w", addr, err)
			}
			pinnedAddr := net.JoinHostPort(pinnedIP.String(), port)
			return pinnedDialer.DialContext(dialCtx, network, pinnedAddr)
		},
		// Reasonable transport-level limits.
		MaxIdleConns:        1,
		IdleConnTimeout:     opts.Timeout,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			result.RedirectCount = len(via)
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects (max %d)", maxRedirects)
			}

			// Re-validate every redirect target.
			redirectURL := req.URL.String()
			newURL, err := ValidateURL(redirectURL)
			if err != nil {
				return fmt.Errorf("redirect URL validation failed: %w", err)
			}

			newIP, err := ResolveAndValidate(newURL.Hostname())
			if err != nil {
				return fmt.Errorf("redirect DNS validation failed: %w", err)
			}

			// Update the transport's dialer to pin to the new IP.
			transport.DialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("bad address %q: %w", addr, err)
				}
				pinnedAddr := net.JoinHostPort(newIP.String(), port)
				return pinnedDialer.DialContext(dialCtx, network, pinnedAddr)
			}

			return nil
		},
	}

	// --- Phase 3: execute the request ---
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validatedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// --- Phase 4: read the body with a size cap ---
	limitedReader := io.LimitReader(resp.Body, opts.MaxBodySize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	if int64(len(body)) > opts.MaxBodySize {
		return nil, fmt.Errorf("response body exceeds maximum size of %d bytes", opts.MaxBodySize)
	}

	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.Body = body
	result.FinalURL = resp.Request.URL.String()

	return result, nil
}

// FetchWithRetry wraps Fetch with a single automatic retry on timeout errors.
// The retry uses double the original timeout.
func FetchWithRetry(ctx context.Context, rawURL string, opts FetchOptions) (*FetchResult, error) {
	result, err := Fetch(ctx, rawURL, opts)
	if err == nil {
		return result, nil
	}

	if !isTimeoutError(err) {
		return nil, err
	}

	// Retry once with 2x timeout.
	opts.Timeout = opts.Timeout * 2
	return Fetch(ctx, rawURL, opts)
}

// isTimeoutError checks whether an error is a timeout-related failure.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "TLS handshake timeout") ||
		strings.Contains(s, "i/o timeout")
}
