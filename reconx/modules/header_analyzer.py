import re
import time
from typing import Any

from reconx.core.module_base import ReconModule
from reconx.core.types import Finding, ModuleError, ModuleResult, ScanConfig, Severity

HSTS_MAX_AGE_MIN = 15552000  # 180 days in seconds


class HeaderAnalyzer(ReconModule):
    name = "header_analyzer"

    def run(self, config: ScanConfig, shared_context: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()
        try:
            raw_headers = shared_context.get("response_headers")
            if not raw_headers:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name,
                        "No response headers available (run url_checker first)",
                        recoverable=True,
                    ),
                )
            headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
            findings = self.analyze_headers(headers)
            return ModuleResult(
                module_name=self.name,
                findings=findings,
                raw={"header_count": len(headers)},
                duration_ms=(time.monotonic() - start) * 1000,
            )
        except Exception as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, str(exc), recoverable=True),
            )

    @staticmethod
    def analyze_headers(headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []

        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append(Finding(
                key="csp.missing",
                title="Content-Security-Policy header missing",
                severity=Severity.MEDIUM,
                detail=(
                    "CSP helps prevent XSS and data injection attacks by "
                    "controlling which resources the browser can load."
                ),
                weight=-15,
            ))

        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            findings.append(Finding(
                key="hsts.missing",
                title="Strict-Transport-Security header missing",
                severity=Severity.MEDIUM,
                detail=(
                    "HSTS tells browsers to always use HTTPS for this site. "
                    "Without it, users are vulnerable to SSL-stripping attacks."
                ),
                weight=-15,
            ))
        else:
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age == 0:
                    findings.append(Finding(
                        key="hsts.max_age_zero",
                        title="HSTS max-age is 0 (disabling HSTS)",
                        severity=Severity.MEDIUM,
                        detail="A max-age of 0 instructs browsers to disable HSTS for this domain.",
                        weight=-10,
                    ))
                elif max_age < HSTS_MAX_AGE_MIN:
                    findings.append(Finding(
                        key="hsts.max_age_low",
                        title="HSTS max-age is below recommended minimum",
                        severity=Severity.LOW,
                        detail=(
                            f"HSTS max-age is {max_age}s. "
                            f"Recommended minimum is {HSTS_MAX_AGE_MIN}s (180 days)."
                        ),
                        weight=-5,
                    ))

        xfo = headers.get("x-frame-options", "")
        if not xfo:
            findings.append(Finding(
                key="x_frame_options.missing",
                title="X-Frame-Options header missing",
                severity=Severity.MEDIUM,
                detail=(
                    "X-Frame-Options prevents clickjacking by controlling "
                    "whether the page can be embedded in a frame."
                ),
                weight=-10,
            ))

        xcto = headers.get("x-content-type-options", "")
        if not xcto:
            findings.append(Finding(
                key="x_content_type_options.missing",
                title="X-Content-Type-Options header missing",
                severity=Severity.LOW,
                detail=(
                    "This header prevents MIME-type sniffing. Without it, "
                    "browsers may interpret files as a different MIME type."
                ),
                weight=-5,
            ))

        xss = headers.get("x-xss-protection", "")
        if xss:
            findings.append(Finding(
                key="x_xss_protection.deprecated",
                title="X-XSS-Protection header present (deprecated)",
                severity=Severity.INFO,
                detail=(
                    "Modern browsers have removed support for X-XSS-Protection. "
                    "Use a Content-Security-Policy instead. This finding is informational only."
                ),
                weight=0,
            ))

        rp = headers.get("referrer-policy", "")
        if not rp:
            findings.append(Finding(
                key="referrer_policy.missing",
                title="Referrer-Policy header missing",
                severity=Severity.LOW,
                detail=(
                    "Referrer-Policy controls how much referrer information "
                    "is included with requests. Without it, browsers use the default."
                ),
                weight=-5,
            ))

        pp = headers.get("permissions-policy", "")
        if not pp:
            findings.append(Finding(
                key="permissions_policy.missing",
                title="Permissions-Policy header missing",
                severity=Severity.LOW,
                detail=(
                    "Permissions-Policy (formerly Feature-Policy) restricts "
                    "browser API access like camera, microphone, and geolocation."
                ),
                weight=-3,
            ))

        cookie_header = headers.get("set-cookie", "")
        if cookie_header:
            cookie_findings = HeaderAnalyzer._analyze_cookies(cookie_header)
            findings.extend(cookie_findings)

        return findings

    @staticmethod
    def _analyze_cookies(raw: str) -> list[Finding]:
        findings: list[Finding] = []
        cookies = _split_set_cookie(raw)
        seen_secure = False
        seen_httponly = False
        seen_samesite = False

        for cookie in cookies:
            flags = cookie.lower()
            if "secure" in flags:
                seen_secure = True
            if "httponly" in flags:
                seen_httponly = True
            if "samesite" in flags:
                seen_samesite = True

        if cookies and not seen_secure:
            findings.append(Finding(
                key="cookie.missing_secure",
                title="Cookie missing Secure flag",
                severity=Severity.MEDIUM,
                detail=(
                    "Cookies without the Secure flag can be sent over "
                    "unencrypted HTTP connections, exposing session data."
                ),
                weight=-10,
            ))
        if cookies and not seen_httponly:
            findings.append(Finding(
                key="cookie.missing_httponly",
                title="Cookie missing HttpOnly flag",
                severity=Severity.MEDIUM,
                detail=(
                    "Cookies without HttpOnly can be accessed by JavaScript, "
                    "making them vulnerable to XSS-based theft."
                ),
                weight=-10,
            ))
        if cookies and not seen_samesite:
            findings.append(Finding(
                key="cookie.missing_samesite",
                title="Cookie missing SameSite attribute",
                severity=Severity.LOW,
                detail=(
                    "Cookies without SameSite may be sent in cross-site "
                    "requests, increasing CSRF risk."
                ),
                weight=-5,
            ))
        return findings


_COOKIE_SPLIT_RE = re.compile(r',\s*(?=[a-zA-Z_][a-zA-Z0-9_]*=)')


def _split_set_cookie(raw: str) -> list[str]:
    return _COOKIE_SPLIT_RE.split(raw)
