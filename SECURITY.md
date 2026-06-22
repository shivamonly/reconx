# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ReconX itself (not in a target scanned by ReconX), please report it privately — do **not** file a public GitHub issue.

Contact: **security@reconx.dev** (placeholder — replace with a real address before public release)

### What to include
- A description of the vulnerability
- Steps to reproduce
- Affected versions
- Any suggested fix (if known)

### Response timeline
- Acknowledgment within 48 hours
- Initial assessment within 5 business days
- Fix or mitigation timeline communicated after assessment

## Scope

This policy covers vulnerabilities in:
- The ReconX source code
- The build and release pipeline
- Dependency supply chain (see our pinned lockfile and pip-audit CI checks)

## Out of Scope

- Vulnerabilities found in targets scanned *by* ReconX
- Best-practice suggestions that are not actual security bugs
- Missing security headers on a target site (ReconX reports these as Findings, not vulnerabilities in itself)
