import os
import re
import time
from typing import Any

import yaml

from reconx.core.module_base import ReconModule
from reconx.core.types import Finding, ModuleError, ModuleResult, ScanConfig, Severity

SIGNATURES_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "signatures.yaml")


class TechDetector(ReconModule):
    name = "tech_detector"

    def run(self, config: ScanConfig, shared_context: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()
        try:
            headers = shared_context.get("response_headers", {})
            body = shared_context.get("response_body", b"")
            html = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)

            findings = self.detect(headers, html)
            return ModuleResult(
                module_name=self.name,
                findings=findings,
                raw={"technologies": [f.key for f in findings]},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, str(exc), recoverable=True),
            )

    @staticmethod
    def detect(headers: dict[str, str], html_snippet: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            with open(SIGNATURES_PATH, encoding="utf-8") as f:
                signatures = yaml.safe_load(f)
        except FileNotFoundError:
            return []

        if not signatures:
            return []

        headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}

        for sig in signatures:
            name: str = sig.get("name", "Unknown")
            category: str = sig.get("category", "unknown")
            confidence: str = sig.get("confidence", "low")
            matched = False

            header_patterns: list[dict[str, str]] = sig.get("header_patterns", [])
            for hp in header_patterns:
                hdr_name = hp["header"].lower()
                hdr_val = headers_lower.get(hdr_name, "")
                if hdr_val:
                    # Bounded regex — no nested quantifiers; see PRD 7.5.
                    # All signature patterns must be reviewable to avoid ReDoS
                    # from attacker-controlled input.
                    try:
                        if re.search(hp["regex"], hdr_val, re.IGNORECASE):
                            matched = True
                            break
                    except re.error:
                        continue

            html_patterns: list[dict[str, str]] = sig.get("html_patterns", [])
            if not matched:
                for hp in html_patterns:
                    try:
                        if re.search(hp["regex"], html_snippet):
                            matched = True
                            break
                    except re.error:
                        continue

            if matched:
                is_header_confirmed = bool(header_patterns and matched)
                display_confidence = confidence if not is_header_confirmed else "high"
                findings.append(Finding(
                    key=f"tech.{name.lower().replace(' ', '_')}",
                    title=name,
                    severity=Severity.INFO,
                    detail=(
                        f"Detected {name} ({category}) "
                        f"[{'observed' if is_header_confirmed else 'guess'} — "
                        f"{display_confidence} confidence]"
                    ),
                    weight=0,
                ))

        return findings
