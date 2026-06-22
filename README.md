# ReconX

Terminal-Based Web Reconnaissance & Security Analyzer.

ReconX is a lightweight, terminal-based tool that lets you assess the **externally observable** security posture of a website — the same class of information a browser, DNS resolver, or CA already discloses publicly.

## Features

- HTTP reachability, latency, and redirect-chain analysis
- Technology fingerprinting from headers and HTML (framework, CMS, server)
- Security header analysis (CSP, HSTS, X-Frame-Options, cookies, and more)
- TLS/SSL certificate inspection (issuer, expiry, self-signed, hostname mismatch)
- Composite security score with transparent, explainable weightings

## Installation

```bash
git clone https://github.com/<org>/reconx
cd reconx
pip install -e .
```

## Usage

```bash
reconx scan example.com
reconx scan example.com --json
reconx scan example.com --headers
reconx scan example.com --ssl
reconx scan example.com --tech
reconx scan example.com --timeout 10 --no-color
```

## Flags

| Flag | Description |
|---|---|
| `--headers` | Run header analysis only |
| `--ssl` | Run SSL/TLS analysis only |
| `--tech` | Run tech detection only |
| `--all` (default) | Run all checks |
| `--json` | Machine-readable JSON output |
| `--timeout <sec>` | Request timeout (default: 5s) |
| `--no-color` | Disable ANSI color output |
| `--verbose`, `-v` | Show request/response metadata |
| `--allow-private-targets` | Allow scanning private/reserved IP ranges |
| `--version` | Print version and exit |

## Security Score

The score starts at 100 and deducts for missing or misconfigured security controls:

| Finding | Weight |
|---|---|
| HTTPS not enforced | -30 |
| Certificate expired | -40 |
| Certificate self-signed | -25 |
| TLS version below 1.2 | -20 |
| HSTS missing | -15 |
| CSP missing | -15 |
| X-Frame-Options missing | -10 |
| Cookie missing Secure/HttpOnly | -10 each |
| And more... | |

Buckets: **Secure** (80-100), **Moderate** (50-79), **Risky** (0-49)

## Limitations

- **Passive only.** ReconX reads what a server voluntarily serves to any anonymous visitor. It does not perform active scanning, brute-forcing, or exploitation.
- Tech detection uses signature matching on headers and HTML. Results are confidence-scored guesses, not certainties.
- No JavaScript execution or headless browser — JS-rendered frameworks may not be detected.

## Responsible Use

ReconX performs passive analysis only. You are responsible for ensuring you have the right to scan any target you specify.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities in ReconX itself.

## License

MIT
