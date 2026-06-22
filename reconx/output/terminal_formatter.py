import re
import sys

from reconx.core.types import ScanReport, Severity

_ANSI_STRIP_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_ALLOWED_CHARS_RE = re.compile(r"[^\x20-\x7e]")


def sanitize_for_terminal(text: str) -> str:
    stripped = _ANSI_STRIP_RE.sub("", text)
    cleaned = _ALLOWED_CHARS_RE.sub("?", stripped)
    return cleaned


SEVERITY_COLORS = {
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[90m",
}
RESET = "\x1b[0m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
RED = "\x1b[31m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"


def _c(text: str, color: str, use_color: bool) -> str:
    if use_color:
        return f"{color}{text}{RESET}"
    return text


def format_terminal(report: ScanReport, no_color: bool = False) -> str:
    use_color = not no_color and sys.stdout.isatty()
    lines: list[str] = []

    target_display = sanitize_for_terminal(report.target)
    final_url_display = sanitize_for_terminal(report.final_url or "N/A")

    lines.append("")
    lines.append(f"[+] Scanning: {target_display}")

    if report.final_url:
        lines.append(f"[i] Final URL: {final_url_display}")
    if report.status_code:
        status_color = GREEN if report.status_code == 200 else YELLOW
        lines.append(
            f"[{_c('OK', GREEN, use_color)}] "
            f"Status: {_c(str(report.status_code), status_color, use_color)}"
        )
    if report.response_time_ms > 0:
        lines.append(f"[i] Response time: {report.response_time_ms:.0f}ms")

    ssl = report.ssl
    if ssl:
        lines.append("")
        lines.append(f"[{_c('SSL', YELLOW, use_color)}] SSL/TLS:")
        lines.append(f"  Issuer: {sanitize_for_terminal(ssl.get('issuer', ''))}")
        lines.append(
            f"  Valid: {ssl.get('valid_from', '')}"
            f" -> {ssl.get('valid_to', '')}"
        )
        days = ssl.get("days_until_expiry")
        if days is not None:
            expiry_color = GREEN if days > 30 else RED
            lines.append(
                f"  Days remaining: "
                f"{_c(str(days), expiry_color, use_color)}"
            )
        lines.append(f"  Protocol: {ssl.get('protocol', '')}")
        match_color = GREEN if ssl.get("hostname_match", True) else RED
        lines.append(
            f"  Hostname match: "
            f"{_c('Yes' if ssl.get('hostname_match', True) else 'No', match_color, use_color)}"
        )

    header_prefixes = ("csp.", "hsts.", "x_", "referrer_", "permissions_", "cookie.")
    header_findings = [f for f in report.findings if f.key.startswith(header_prefixes)]
    if header_findings or ssl:
        lines.append("")
        lines.append(f"[{_c('HEADERS', YELLOW, use_color)}] Security Headers:")
        all_header_keys = {
            "csp": "Content-Security-Policy",
            "hsts": "Strict-Transport-Security",
            "x_frame_options": "X-Frame-Options",
            "x_content_type_options": "X-Content-Type-Options",
            "x_xss_protection": "X-XSS-Protection",
            "referrer_policy": "Referrer-Policy",
            "permissions_policy": "Permissions-Policy",
        }
        header_finding_map = {f.key: f for f in header_findings}
        for key, display_name in all_header_keys.items():
            matched = [f for f_key, f in header_finding_map.items() if f_key.startswith(key)]
            if matched:
                f = matched[0]
                sev_color = SEVERITY_COLORS.get(f.severity, DIM)
                weight_str = f"({f.weight})" if f.weight < 0 else ""
                lines.append(
                    f"  {display_name}: "
                    f"{_c('Missing', sev_color, use_color)}"
                    f"{'  ' + _c(weight_str, DIM, use_color) if weight_str else ''}"
                    if f.weight < 0
                    else f"  {display_name}: {_c('Present (deprecated)', YELLOW, use_color)}"
                )
            else:
                lines.append(f"  {display_name}: {_c('Present', GREEN, use_color)}")

    cookie_findings = [f for f in report.findings if f.key.startswith("cookie.")]
    for cf in cookie_findings:
        sev_color = SEVERITY_COLORS.get(cf.severity, DIM)
        flag_name = cf.key.split(".", 1)[1] if "." in cf.key else cf.key
        lines.append(
            f"  Set-Cookie {flag_name}: "
            f"{_c('Missing', sev_color, use_color)}  ({cf.weight})"
        )

    tech = report.tech
    if tech:
        lines.append("")
        lines.append(f"[{_c('TECH', YELLOW, use_color)}] Tech Stack:")
        for t in tech:
            display_name = sanitize_for_terminal(t["name"])
            confidence_str = t.get("confidence", "")
            if "observed" in confidence_str.lower() or "high" in confidence_str.lower():
                tag = _c("[observed]", GREEN, use_color)
            else:
                tag = _c("[guess]", YELLOW, use_color)
            lines.append(f"  {display_name}: {tag}")

    score = report.score_value
    bucket = report.score_bucket
    if score >= 80:
        score_color = GREEN
    elif score >= 50:
        score_color = YELLOW
    else:
        score_color = RED
    lines.append("")
    lines.append(
        f"[{_c('SCORE', YELLOW, use_color)}] "
        f"Security Score: {_c(f'{score}/100', score_color, use_color)} "
        f"({bucket})"
    )

    deductions = [f for f in report.findings if f.weight < 0]
    if deductions:
        lines.append("  Deductions:")
        for d in deductions:
            sev_color = SEVERITY_COLORS.get(d.severity, DIM)
            lines.append(
                f"    {_c(d.key, sev_color, use_color)} ({d.weight})"
            )

    if report.errors:
        lines.append("")
        for e in report.errors:
            lines.append(f"  [!] [{e.module}] {sanitize_for_terminal(e.message)}")

    lines.append("")
    return "\n".join(lines)
