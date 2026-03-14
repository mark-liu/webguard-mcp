package fetch

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// blockedNets contains CIDR ranges that must never be connected to.
var blockedNets []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local
		"fe80::/10",      // IPv6 link-local
		"100.64.0.0/10",  // carrier-grade NAT (RFC 6598)
		"fc00::/7",       // IPv6 unique local
		// IPv4-mapped IPv6 (::ffff:x.x.x.x) is handled by To4() extraction
		// in ValidateIP — the embedded IPv4 is checked against all ranges.
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("bad CIDR in blocklist: %s: %v", cidr, err))
		}
		blockedNets = append(blockedNets, ipNet)
	}
}

// cloudMetadataIPs are specific IPs used by cloud providers for instance metadata.
var cloudMetadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"),     // AWS / GCP / Azure
	net.ParseIP("fd00:ec2::254"),       // AWS IPv6 metadata
	net.ParseIP("169.254.170.2"),       // AWS ECS task metadata
	net.ParseIP("169.254.169.123"),     // AWS NTP
	net.ParseIP("100.100.100.200"),     // Alibaba Cloud metadata
	net.ParseIP("169.254.169.250"),     // Oracle Cloud metadata
	net.ParseIP("169.254.169.251"),     // Oracle Cloud metadata
	net.ParseIP("169.254.169.252"),     // Oracle Cloud metadata
	net.ParseIP("169.254.169.253"),     // Oracle Cloud metadata
}

// cloudMetadataHosts are hostnames that resolve to metadata services.
var cloudMetadataHosts = []string{
	"metadata.google.internal",
	"metadata.goog",
}

// ValidateURL checks a URL for SSRF vectors and returns the parsed, validated URL.
// HTTP URLs are upgraded to HTTPS. Returns an error if the URL is unsafe.
func ValidateURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Require http or https scheme.
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "https" // upgrade to HTTPS
	case "https":
		// ok
	default:
		return nil, fmt.Errorf("unsupported scheme %q: only http and https are allowed", u.Scheme)
	}

	// Reject userinfo (e.g. http://evil.com@169.254.169.254).
	if u.User != nil {
		return nil, fmt.Errorf("URLs with userinfo are not allowed")
	}

	// Reject @ in the raw authority even if Go's parser didn't pick it up.
	if strings.Contains(rawURL, "@") {
		return nil, fmt.Errorf("URLs containing '@' in authority section are not allowed")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("URL has no hostname")
	}

	// Reject URL-encoded hostname components.
	if strings.ContainsAny(host, "%") {
		return nil, fmt.Errorf("URL-encoded hostname components are not allowed")
	}

	// Check for metadata hostnames.
	lower := strings.ToLower(host)
	for _, mh := range cloudMetadataHosts {
		if lower == mh {
			return nil, fmt.Errorf("hostname %q resolves to a cloud metadata service", host)
		}
	}

	// Detect octal IP notation (e.g. 0177.0.0.1 for 127.0.0.1).
	if err := rejectOctalIP(host); err != nil {
		return nil, err
	}

	return u, nil
}

// rejectOctalIP detects if a dotted-decimal host uses octal notation in any
// component (leading zero followed by another digit, e.g. 0177, 012).
func rejectOctalIP(host string) error {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return nil // not an IPv4 literal
	}
	for _, p := range parts {
		if len(p) == 0 {
			return nil // not a valid IP literal, let DNS handle it
		}
		// A component with a leading zero followed by at least one more digit
		// is octal notation. "0" alone is fine.
		if len(p) > 1 && p[0] == '0' {
			allDigits := true
			for _, c := range p {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return fmt.Errorf("octal IP notation detected in %q: potential SSRF bypass", host)
			}
		}
	}
	return nil
}

// ValidateIP checks whether an IP address is safe to connect to.
// Returns an error if the IP falls within a blocked range or matches a
// cloud metadata endpoint.
func ValidateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("nil IP address")
	}

	// For IPv4-mapped IPv6 addresses, also validate the embedded IPv4.
	if ipv4 := ip.To4(); ipv4 != nil {
		if err := validateIPInner(ipv4); err != nil {
			return err
		}
	}

	return validateIPInner(ip)
}

func validateIPInner(ip net.IP) error {
	for _, ipNet := range blockedNets {
		if ipNet.Contains(ip) {
			return fmt.Errorf("IP %s falls within blocked range %s", ip, ipNet)
		}
	}

	for _, metaIP := range cloudMetadataIPs {
		if ip.Equal(metaIP) {
			return fmt.Errorf("IP %s is a cloud metadata endpoint", ip)
		}
	}

	return nil
}

// ResolveAndValidate performs DNS resolution on the given host and validates
// every returned IP address. It returns the first safe IP for DNS-pinned
// connections. If all resolved IPs are unsafe, an error is returned.
func ResolveAndValidate(host string) (net.IP, error) {
	// If the host is already an IP literal, validate and return it directly.
	if ip := net.ParseIP(host); ip != nil {
		if err := ValidateIP(ip); err != nil {
			return nil, fmt.Errorf("IP %s is blocked: %w", host, err)
		}
		return ip, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS resolution returned no addresses for %q", host)
	}

	// ALL resolved IPs must be safe — one blocked IP means the host is rejected.
	for _, ip := range ips {
		if err := ValidateIP(ip); err != nil {
			return nil, fmt.Errorf("host %q resolved to blocked IP: %w", host, err)
		}
	}

	// Prefer IPv4 addresses — many networks have broken or slow IPv6, and the
	// pinned dialer bypasses Go's happy-eyeballs fallback.
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	return ips[0], nil
}
