---
id: webguard-mcp
name: WebGuard MCP
version: 0.1.0
description: Secure web fetching for LLM agents — prompt injection scanning before content enters context
license: MIT
language: go
transport: stdio
tools:
  - name: webguard_fetch
    description: Fetch URL with prompt injection scanning
  - name: webguard_status
    description: Server health and config status
inspired_by:
  - name: Agent Wall
    url: https://github.com/agent-wall/agent-wall
    license: MIT
  - name: MCP Guard
    url: https://github.com/General-Analysis/mcp-guard
    license: MIT
  - name: Lasso claude-hooks
    url: https://github.com/lasso-security/claude-hooks
    license: MIT
---

# WebGuard MCP

Secure web fetching MCP server for LLM agents. Scans fetched content for prompt injection attacks **before** it enters the LLM context window. Malicious content is blocked entirely — zero leaked tokens.

## Why

LLM agents fetch web content that can contain prompt injection attacks. Existing solutions either warn after content is already in context (too late), require cloud API calls (privacy/latency), or add proxy complexity. WebGuard IS the web fetcher — classification happens inside the tool, so injections never reach the LLM.

- **Zero cloud** — all classification runs locally. Your data never leaves the machine.
- **Total protection** — content blocked before entering LLM context, not post-hoc warnings.
- **Performance-first** — 10MB Go binary, ~1ms classifier on typical pages.
- **Drop-in** — one `claude mcp add` command, replaces WebFetch transparently.

## Install

```bash
# From source
go install github.com/mark-liu/webguard-mcp/cmd/webguard-mcp@latest

# Or build locally
git clone https://github.com/mark-liu/webguard-mcp
cd webguard-mcp
make build
```

### macOS Firewall

macOS firewall blocks unsigned binaries from making network connections. If fetches time out, allow the binary through:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/webguard-mcp
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /path/to/webguard-mcp
```

## Usage

```bash
# Add to Claude Code
claude mcp add webguard -s user -- /path/to/webguard-mcp

# Then in Claude Code:
# "use webguard to fetch https://example.com"
```

## Architecture

```
Claude Code → webguard_fetch(url)
                    │
        ┌───────────┴───────────┐
        │ 1. URL Validation     │  SSRF prevention, scheme check
        │ 2. DNS Pinning        │  Resolve + validate all IPs
        │ 3. HTTP Fetch         │  HTTPS, max 5 redirects, 5MB limit
        │ 4. Content Extraction │  HTML → markdown, strip scripts
        │ 5. Preprocessing      │  Comment extraction, entity decode,
        │                       │  base64/URL/hex decode, NFC normalize,
        │                       │  zero-width strip
        │ 6. Stage 1: Patterns  │  Aho-Corasick + regex (~1ms)
        │ 7. Stage 2: Heuristic │  Density, clustering, proximity
        │ 8. Decision           │  PASS → content | BLOCK → zero content
        │ 9. Audit Log          │  JSONL with pattern IDs + timing
        └───────────────────────┘
```

## Tools

### `webguard_fetch`

Fetches a URL with SSRF protection and prompt injection scanning.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | URL to fetch (http/https) |
| `headers` | object | no | Custom HTTP headers |
| `raw` | boolean | no | Return raw HTML instead of markdown |

**On PASS**: returns extracted markdown content + metadata.
**On BLOCK**: returns `[BLOCKED: prompt injection detected]` + metadata. Zero page content leaked.

### `webguard_status`

Returns server health: version, pattern count, sensitivity, config.

## Classifier

Two-stage cascade — fast pattern match, then heuristic scoring only when needed.

### Stage 1: Pattern Match

38 patterns across 8 categories via hybrid Aho-Corasick (literals, single O(N) pass) + regex (structural patterns):

| Category | Patterns | Examples |
|----------|----------|----------|
| instruction-override | 7 | "ignore previous instructions", "from now on you will" |
| prompt-marker | 6 | `<\|im_start\|>system`, `[SYSTEM]:`, `<<SYS>>` |
| authority-claim | 6 | "I am your developer", "DAN mode" |
| exfil-instruction | 5 | "send all data to", hidden image markdown |
| output-manipulation | 4 | "respond only with", "do not mention" |
| unicode-obfuscation | 4 | zero-width sequences, RTL overrides |
| encoded-injection | 3 | `eval(atob())`, base64_decode |
| delimiter-injection | 3 | `---END SYSTEM PROMPT---`, `{"role":"system"}` |

### Stage 2: Heuristic Scoring

Only runs when Stage 1 finds non-critical matches. Factors:

- **Density**: matches per 1000 chars (>2.0 = 1.2x multiplier)
- **Clustering**: matches within 200 chars of each other (1.5x)
- **Proximity**: authority-claim + instruction-override nearby (1.5x)
- **Encoding penalty**: decoded content matches (1.3x)

### Sensitivity Levels

| Level | Threshold | Use Case |
|-------|-----------|----------|
| `low` | 2.0 | Documentation, trusted sources |
| `medium` | 1.0 | General browsing (default) |
| `high` | 0.5 | Untrusted sources |

## SSRF Prevention

All checks before any TCP connection:

- Private IP ranges (RFC 1918, loopback, link-local, carrier-grade NAT)
- Cloud metadata (AWS, GCP, Azure, Alibaba, Oracle, ECS)
- Octal IP detection (`0177.0.0.01`)
- URL-encoded hostname rejection
- `@` in URL authority rejection
- DNS pinning (resolve once, connect to resolved IP)
- Re-validate on every redirect hop (max 5)

## Configuration

`~/.config/webguard-mcp/config.yaml` — works with zero config (sensible defaults):

```yaml
sensitivity: medium          # low, medium, high
max_body_size: 5242880       # 5MB
request_timeout: 15s
domains:
  "docs.python.org":
    sensitivity: low         # trust documentation sites
  "*.github.com":
    sensitivity: low
allowlist: []                # empty = allow all
blocklist: ["*.evil.com"]
audit:
  enabled: true
  path: ""                   # default: ~/.local/share/webguard-mcp/audit.jsonl
```

## Performance

Benchmarked on Apple M4:

| Content Size | Stage 1 | Full Pipeline | Allocations |
|-------------|---------|---------------|-------------|
| 1 KB | 0.2 ms | ~0.3 ms | 8 allocs |
| 10 KB | 2.5 ms | ~2.6 ms | 8 allocs |
| 100 KB | 28 ms | ~29 ms | 9 allocs |

Typical web pages extract to 5-20KB markdown, putting real-world overhead at 1-3ms per fetch.

## Design Decisions

- **Binary pass/block, no redaction** — redaction gives false safety; attackers can craft payloads that survive partial removal.
- **No ML stage** — keeps binary <20MB, no model files, <10ms total. If false negatives prove high, add optional embedding model in v2.
- **No search tool** — search needs upstream API = cloud dependency. Users keep their existing WebSearch.
- **HTTPS upgrade** — HTTP URLs are silently upgraded to HTTPS.
- **Aho-Corasick + regex hybrid** — single O(N) DFA pass for literals; regex only for structural patterns that need captures/alternation.

## Development

```bash
make build          # Build binary
make test           # Run all tests
make bench          # Run classifier benchmarks
make bench-real     # Fetch real URLs and measure overhead
make lint           # go vet + staticcheck
```

## Project Structure

```
webguard-mcp/
├── cmd/
│   ├── webguard-mcp/main.go        # Entry point
│   └── benchmark/main.go           # Real-world URL benchmark
├── internal/
│   ├── server/server.go            # MCP tool registration + handlers
│   ├── fetch/
│   │   ├── client.go               # HTTP client, SSRF-safe redirects
│   │   ├── ssrf.go                 # URL + IP validation
│   │   └── extract.go              # HTML → markdown
│   ├── classify/
│   │   ├── engine.go               # Two-stage orchestrator
│   │   ├── preprocess.go           # 7-step content preprocessing
│   │   ├── stage1.go               # Aho-Corasick + regex scanner
│   │   ├── stage2.go               # Heuristic scoring
│   │   ├── patterns.go             # 38 pattern definitions
│   │   ├── encoding.go             # Base64/URL/hex decode
│   │   └── result.go               # Result types
│   ├── config/config.go            # YAML config + domain overrides
│   └── audit/logger.go             # JSONL audit writer
└── testdata/
    ├── malicious/                   # Injection payloads (7 files)
    ├── benign/                      # Clean content (3 files)
    ├── edge_cases/                  # Security docs
    └── encoded/                     # Base64-encoded payloads
```

## License

MIT
