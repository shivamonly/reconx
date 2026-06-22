from reconx.core.types import Severity
from reconx.modules.header_analyzer import HeaderAnalyzer


class TestHeaderAnalyzer:
    def test_all_headers_present(self) -> None:
        headers = {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        }
        findings = HeaderAnalyzer.analyze_headers(headers)
        missing = {f.key for f in findings if f.weight < 0}
        assert missing == set(), f"Unexpected deductions: {missing}"

    def test_all_headers_missing(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({})
        keys = {f.key for f in findings}
        expected = {
            "csp.missing", "hsts.missing", "x_frame_options.missing",
            "x_content_type_options.missing", "referrer_policy.missing",
            "permissions_policy.missing",
        }
        assert keys == expected, f"Got {keys}, expected {expected}"
        for f in findings:
            assert f.weight < 0 or f.severity == Severity.INFO

    def test_hsts_max_age_zero(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({
            "strict-transport-security": "max-age=0",
        })
        keys = {f.key for f in findings}
        assert "hsts.max_age_zero" in keys
        assert "hsts.missing" not in keys

    def test_hsts_max_age_low(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({
            "strict-transport-security": "max-age=86400",
        })
        keys = {f.key for f in findings}
        assert "hsts.max_age_low" in keys

    def test_hsts_max_age_sufficient(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({
            "strict-transport-security": "max-age=31536000",
        })
        keys = {f.key for f in findings}
        assert "hsts.max_age_low" not in keys
        assert "hsts.max_age_zero" not in keys

    def test_x_xss_protection_present_is_informational(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({
            "x-xss-protection": "1; mode=block",
        })
        xss = [f for f in findings if f.key.startswith("x_xss")]
        assert len(xss) == 1
        assert xss[0].severity == Severity.INFO
        assert xss[0].weight == 0

    def test_set_cookie_secure_and_httponly(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({
            "set-cookie": "sessionid=abc123; Secure; HttpOnly; Path=/",
        })
        cookie_keys = {f.key for f in findings}
        assert "cookie.missing_secure" not in cookie_keys
        assert "cookie.missing_httponly" not in cookie_keys

    def test_set_cookie_missing_flags(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({
            "set-cookie": "sessionid=abc123; Path=/",
        })
        keys = {f.key for f in findings}
        assert "cookie.missing_secure" in keys
        assert "cookie.missing_httponly" in keys
        assert "cookie.missing_samesite" in keys

    def test_multiple_set_cookies_mixed_flags(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({
            "set-cookie": (
                "sessionid=abc; Secure; HttpOnly; Path=/, "
                "csrftoken=xyz; Path=/"
            ),
        })
        keys = {f.key for f in findings}
        assert "cookie.missing_secure" not in keys
        assert "cookie.missing_httponly" not in keys

    def test_permissions_policy_missing_weight(self) -> None:
        findings = HeaderAnalyzer.analyze_headers({})
        pp = [f for f in findings if f.key == "permissions_policy.missing"]
        assert len(pp) == 1
        assert pp[0].weight == -3
