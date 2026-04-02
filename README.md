# WebGuard MCP (Go — superseded)

> **This project has been rewritten in Rust: [webguard](https://github.com/mark-liu/webguard)**
>
> The Rust version has the same security model, same test suite, and same 38 built-in patterns — plus smaller binary (6MB vs 10MB), no GC pauses, streaming body reads, and per-hop redirect SSRF re-validation. Use the Rust version for new installations.

---

Secure web fetching MCP server for LLM agents. Scans fetched content for prompt injection attacks **before** it enters the LLM context window. Malicious content is blocked entirely — zero leaked tokens.

## Why

LLM agents fetch web content that can contain prompt injection attacks. Existing solutions either warn after content is already in context (too late), require cloud API calls (privacy/latency), or add proxy complexity. WebGuard IS the web fetcher — classification happens inside the tool, so injections never reach the LLM.

- **Zero cloud** — all classification runs locally. Your data never leaves the machine.
- **Total protection** — content blocked before entering LLM context, not post-hoc warnings.
- **Performance-first** — 10MB Go binary, ~1ms classifier on typical pages.
- **Drop-in** — one `claude mcp add` command, replaces WebFetch transparently.

## Install

```bash
# Homebrew (macOS/Linux)
brew install mark-liu/tap/webguard-mcp

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

# Then use webguard_fetch in Claude Code to retrieve any URL
```

## Architecture

```
Claude Code → webguard_fetch(url)
                    │
        ┌───────────┴───────────┐
        │ 1. URL Validation     │  SSRF prevention, scheme check
        │ 2. DNS Pinning        │  Resolve + validate all IPs
        │ 3. HTTP Fetch         │  HTTPS, retry on timeout, 5MB limit
        │ 4. Content Extraction │  HTML → markdown, strip scripts
        │ 5. Preprocessing      │  Comment extraction, entity decode,
        │                       │  base64/URL/hex decode, NFC normalize,
        │                       │  zero-width strip
        │ 6. Stage 1: Patterns  │  Aho-Corasick + regex (~1ms)
        │    ↳ Category filter  │  Suppress per-domain categories
        │    ↳ Doc-path hints   │  Auto-suppress for /docs/, /api/
        │ 7. Stage 2: Heuristic │  Density, clustering, proximity
        │ 8. Decision           │  PASS/WARN/BLOCK based on mode
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
| `max_chars` | number | no | Truncate response to N characters (0 = unlimited) |

**On PASS**: returns extracted markdown content + metadata (including risk score and any non-blocking pattern matches).
**On WARN** (mode=warn): returns content with a warning banner + metadata. Content is delivered but flagged.
**On BLOCK** (mode=block, default): returns `[BLOCKED: prompt injection detected]` + metadata. Zero page content leaked.

### `webguard_status`

Returns server health: version, pattern count, mode, sensitivity, config.

### `webguard_report`

Returns an audit report aggregated from the JSONL audit log.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `days` | number | no | Number of days to include (default: 7) |

Report includes: verdict breakdown, top triggered patterns, blocked/warned domains, average timing.

## Modes

| Mode | Behaviour | Use Case |
|------|-----------|----------|
| `block` (default) | Blocks content entirely on detection | Production, high-security |
| `warn` | Returns content with a warning banner | Onboarding, tuning false positives |

Set via config: `mode: warn` or `mode: block`.

## Classifier

Two-stage cascade — fast pattern match, then heuristic scoring only when needed.

### Stage 1: Pattern Match

38 built-in patterns across 8 categories via hybrid Aho-Corasick (literals, single O(N) pass) + regex (structural patterns). Additional patterns can be loaded from external YAML files.

| Category | Patterns | Description |
|----------|----------|-------------|
| instruction-override | 7 | Attempts to override or reset prior instructions |
| prompt-marker | 6 | Fake system/instruction delimiters and chat markers |
| authority-claim | 6 | False claims of developer, admin, or elevated access |
| exfil-instruction | 5 | Data exfiltration via URLs or hidden elements |
| output-manipulation | 4 | Attempts to constrain or redirect model output |
| unicode-obfuscation | 4 | Zero-width chars, RTL overrides, Private Use Area |
| encoded-injection | 3 | Base64/eval/charcode obfuscated payloads |
| delimiter-injection | 3 | Fake prompt boundaries and role injections |

See [PATTERNS.md](PATTERNS.md) for the full pattern list with examples and regex definitions.

### Category Suppression

Suppress specific pattern categories per domain to eliminate false positives without lowering overall sensitivity:

```yaml
domains:
  "*.linkedin.com":
    suppress: ["authority-claim"]     # "I am the developer" in profiles
  "interactivebrokers.com":
    suppress: ["encoded-injection"]   # base64 in API docs
  "google.com":
    suppress: ["unicode-obfuscation"] # PUA chars in Finance HTML
```

Documentation URLs (`/docs/`, `/api/`, `/reference/`, `/sdk/`, etc.) automatically suppress `exfil-instruction` and `encoded-injection` categories.

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
mode: block                  # block or warn
max_body_size: 5242880       # 5MB
request_timeout: 15s
patterns_dir: ""             # path to external pattern YAML files

domains:
  "docs.python.org":
    sensitivity: low         # trust documentation sites
    timeout: 30s             # per-domain timeout
  "*.github.com":
    sensitivity: low
  "*.linkedin.com":
    suppress:                # suppress false-positive categories
      - authority-claim
  "interactivebrokers.com":
    suppress:
      - encoded-injection

allowlist: []                # empty = allow all
blocklist: ["*.evil.com"]

audit:
  enabled: true
  path: ""                   # default: ~/.local/share/webguard-mcp/audit.jsonl
```

Send `SIGHUP` to reload config (including external patterns) without restarting:

```bash
kill -HUP $(pgrep webguard-mcp)
```

## External Patterns

Add custom detection patterns by placing YAML files in the `patterns_dir` directory:

```yaml
# patterns.d/custom.yaml
patterns:
  - id: custom-001
    category: instruction-override
    severity: high
    type: literal                    # or "regex"
    value: "override all safety measures"

  - id: custom-002
    category: exfil-instruction
    severity: critical
    type: regex
    value: "(?i)extract\\s+(and\\s+)?send\\s+(to|via)"
```

External patterns are merged with built-in patterns at startup and on config reload.

## Timeout Retry

Fetches that time out are automatically retried once with double the timeout. Per-domain timeouts can be configured:

```yaml
domains:
  "slow-enterprise-site.com":
    timeout: 45s
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

- **Block + warn modes** — `block` for production (zero content leak), `warn` for onboarding (content + warning banner). No redaction — it gives false safety.
- **Category suppression over global sensitivity** — surgical false-positive elimination without weakening detection for other categories.
- **Timeout retry** — single automatic retry with 2x timeout on network failures, configurable per domain.
- **No ML stage (yet)** — keeps binary <20MB, no model files, <10ms total. External pattern contributions bridge the gap.
- **No search tool** — search needs upstream API = cloud dependency. Users keep their existing WebSearch.
- **HTTPS upgrade** — HTTP URLs are silently upgraded to HTTPS.
- **Aho-Corasick + regex hybrid** — single O(N) DFA pass for literals; regex only for structural patterns that need captures/alternation.
- **Doc-path auto-suppression** — URLs containing `/docs/`, `/api/`, `/reference/`, etc. automatically suppress categories that commonly false-positive on documentation content.

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
│   │   ├── client.go               # HTTP client, SSRF-safe redirects, retry
│   │   ├── ssrf.go                 # URL + IP validation
│   │   └── extract.go              # HTML → markdown
│   ├── classify/
│   │   ├── engine.go               # Two-stage orchestrator + ClassifyWithOptions
│   │   ├── preprocess.go           # 8-step content preprocessing
│   │   ├── stage1.go               # Aho-Corasick + regex scanner
│   │   ├── stage2.go               # Heuristic scoring
│   │   ├── patterns.go             # 38 built-in pattern definitions
│   │   ├── external.go             # External pattern YAML loader
│   │   ├── encoding.go             # Base64/URL/hex decode
│   │   └── result.go               # Result types (pass/block/warn)
│   ├── config/config.go            # YAML config + domain overrides + suppress
│   └── audit/logger.go             # JSONL audit writer + reader
├── patterns.d/                      # External pattern directory (example)
└── testdata/
    ├── malicious/                   # Injection payloads (8 files)
    ├── benign/                      # Clean content (3 files)
    ├── edge_cases/                  # Security docs
    └── encoded/                     # Base64-encoded payloads
```

## Related Projects

- **[webguard (Rust)](https://github.com/mark-liu/webguard)** — Rust rewrite of this project. Smaller binary, no GC, streaming body reads, per-hop redirect SSRF validation. Use this for new installations.
- **[mcpguard](https://github.com/mark-liu/mcpguard)** — same idea, different input. WebGuard scans web content fetched via HTTP. mcpguard scans MCP tool results (Discord messages, Telegram chats, any user-generated content returned by MCP servers). If you're worried about prompt injection from chat platforms rather than web pages, use mcpguard.
- **[snap](https://github.com/mark-liu/snap)** — MCP stdio compression proxy for Playwright snapshots. Same proxy architecture as mcpguard but focused on token savings rather than security.

## License

MIT

## MCP Registry Metadata

<!-- Machine-readable metadata for MCP registries and discovery tools. Not for humans. -->

```yaml
id: webguard-mcp
name: WebGuard MCP
description: Secure web fetching for LLM agents — prompt injection scanning before content enters context
license: MIT
language: go
transport: stdio
tools:
  - name: webguard_fetch
    description: Fetch URL with prompt injection scanning
  - name: webguard_status
    description: Server health and config status
  - name: webguard_report
    description: Audit report with usage statistics
```
