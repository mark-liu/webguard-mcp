package fetch

import (
	"net"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		wantErr    bool
		wantScheme string // expected scheme if no error
	}{
		{
			name:       "valid HTTPS URL",
			rawURL:     "https://example.com/path",
			wantErr:    false,
			wantScheme: "https",
		},
		{
			name:       "HTTP upgraded to HTTPS",
			rawURL:     "http://example.com/path",
			wantErr:    false,
			wantScheme: "https",
		},
		{
			name:    "URL with @ in authority",
			rawURL:  "https://evil.com@169.254.169.254",
			wantErr: true,
		},
		{
			name:    "URL with userinfo",
			rawURL:  "https://user:pass@example.com",
			wantErr: true,
		},
		{
			name:    "URL-encoded hostname",
			rawURL:  "https://ex%61mple.com/path",
			wantErr: true,
		},
		{
			name:    "octal IP notation",
			rawURL:  "https://0177.0.0.01/path",
			wantErr: true,
		},
		{
			name:    "ftp scheme",
			rawURL:  "ftp://example.com/file",
			wantErr: true,
		},
		{
			name:    "no scheme",
			rawURL:  "example.com/path",
			wantErr: true,
		},
		{
			name:    "empty URL",
			rawURL:  "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ValidateURL(tc.rawURL)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ValidateURL(%q) = %v, nil; want error", tc.rawURL, u)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateURL(%q) unexpected error: %v", tc.rawURL, err)
			}
			if u.Scheme != tc.wantScheme {
				t.Errorf("ValidateURL(%q).Scheme = %q, want %q", tc.rawURL, u.Scheme, tc.wantScheme)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{
			name:    "public IPv4",
			ip:      "8.8.8.8",
			wantErr: false,
		},
		{
			name:    "loopback",
			ip:      "127.0.0.1",
			wantErr: true,
		},
		{
			name:    "private 10.x",
			ip:      "10.0.0.1",
			wantErr: true,
		},
		{
			name:    "private 172.16.x",
			ip:      "172.16.0.1",
			wantErr: true,
		},
		{
			name:    "private 192.168.x",
			ip:      "192.168.1.1",
			wantErr: true,
		},
		{
			name:    "link-local",
			ip:      "169.254.1.1",
			wantErr: true,
		},
		{
			name:    "AWS metadata",
			ip:      "169.254.169.254",
			wantErr: true,
		},
		{
			name:    "carrier-grade NAT",
			ip:      "100.64.0.1",
			wantErr: true,
		},
		{
			name:    "IPv6 loopback",
			ip:      "::1",
			wantErr: true,
		},
		{
			name:    "IPv4-mapped IPv6 loopback",
			ip:      "::ffff:127.0.0.1",
			wantErr: true,
		},
		{
			name:    "public IPv6",
			ip:      "2001:db8::1",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", tc.ip)
			}
			err := ValidateIP(ip)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateIP(%s) = nil, want error", tc.ip)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateIP(%s) = %v, want nil", tc.ip, err)
			}
		})
	}
}
