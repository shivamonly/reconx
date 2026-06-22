from datetime import datetime, timezone
from typing import Any

from reconx.core.types import Finding, ModuleError, ModuleResult, ScanReport

BASE_WEIGHTS: dict[str, int] = {
    "https_missing": -30,
    "csp.missing": -15,
    "hsts.missing": -15,
    "x_frame_options.missing": -10,
    "x_content_type_options.missing": -5,
    "referrer_policy.missing": -5,
    "cert.expired": -40,
    "cert.expiring_soon_30d": -10,
    "cert.self_signed": -25,
    "tls.below_1_2": -20,
    "cookie.missing_secure": -10,
    "cookie.missing_httponly": -10,
}

FINDING_KEY_OVERRIDES: dict[str, int] = {}


def resolve_weight(finding: Finding) -> int:
    if finding.key in FINDING_KEY_OVERRIDES:
        return FINDING_KEY_OVERRIDES[finding.key]
    return BASE_WEIGHTS.get(finding.key, finding.weight)


def build_report(results: list[ModuleResult], target: str = "") -> ScanReport:
    all_findings: list[Finding] = []
    errors: list[ModuleError] = []
    ssl_info: dict[str, Any] = {}
    headers_info: dict[str, Any] = {}
    tech_list: list[dict[str, Any]] = []
    final_url: str | None = None
    status_code: int | None = None
    response_time_ms: float = 0.0

    for mr in results:
        all_findings.extend(mr.findings)

        if mr.error:
            errors.append(mr.error)

        if mr.module_name == "url_checker" and mr.error is None:
            final_url = mr.raw.get("final_url")
            status_code = mr.raw.get("status_code")
            response_time_ms = mr.duration_ms

        if mr.module_name == "ssl_checker" and mr.error is None:
            ssl_info = {
                "issuer": mr.raw.get("issuer", ""),
                "valid_from": mr.raw.get("valid_from", ""),
                "valid_to": mr.raw.get("valid_to", ""),
                "days_until_expiry": mr.raw.get("days_until_expiry"),
                "self_signed": mr.raw.get("self_signed", False),
                "hostname_match": mr.raw.get("hostname_match", True),
                "protocol": mr.raw.get("protocol", ""),
            }

        if mr.module_name == "header_analyzer" and mr.error is None:
            headers_info = {
                "header_count": mr.raw.get("header_count", 0),
            }

        if mr.module_name == "tech_detector" and mr.error is None:
            tech_list = [
                {"name": f.title, "category": "", "confidence": f.detail}
                for f in mr.findings
            ]

    total_weight = 0
    for f in all_findings:
        total_weight += resolve_weight(f)

    score_value = max(0, min(100, 100 + total_weight))

    if score_value >= 80:
        bucket = "Secure"
    elif score_value >= 50:
        bucket = "Moderate"
    else:
        bucket = "Risky"

    return ScanReport(
        target=target,
        final_url=final_url,
        status_code=status_code,
        ssl=ssl_info,
        headers=headers_info,
        tech=tech_list,
        findings=all_findings,
        score_value=score_value,
        score_bucket=bucket,
        errors=errors,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        response_time_ms=response_time_ms,
    )
