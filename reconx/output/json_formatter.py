import json
from typing import Any

from reconx.core.types import ScanReport


def format_json(report: ScanReport) -> str:
    data: dict[str, Any] = {
        "reconx_version": report.reconx_version,
        "target": report.target,
        "scanned_at": report.scanned_at,
        "final_url": report.final_url,
        "status_code": report.status_code,
        "response_time_ms": report.response_time_ms,
        "ssl": report.ssl,
        "headers": report.headers,
        "tech": [
            {
                "name": t["name"],
                "category": "",
                "confidence": _extract_confidence(t.get("confidence", "")),
            }
            for t in report.tech
        ],
        "findings": [
            {
                "key": f.key,
                "severity": f.severity.value,
                "weight": f.weight,
                "detail": f.detail,
            }
            for f in report.findings
        ],
        "score": {
            "value": report.score_value,
            "bucket": report.score_bucket,
        },
        "errors": [
            {
                "module": e.module,
                "message": e.message,
            }
            for e in report.errors
        ],
    }

    return json.dumps(data, indent=2, ensure_ascii=False)


def _extract_confidence(detail: str) -> str:
    if "high" in detail.lower():
        return "high"
    if "medium" in detail.lower():
        return "medium"
    if "low" in detail.lower():
        return "low"
    return "unknown"
