from reconx.core.score_engine import build_report, BASE_WEIGHTS
from reconx.core.types import Finding, ModuleResult, Severity


def _make_result(findings: list[Finding], module: str = "test") -> ModuleResult:
    return ModuleResult(module_name=module, findings=findings)


class TestScoreEngine:
    def test_empty_results_scores_100(self) -> None:
        report = build_report([], target="example.com")
        assert report.score_value == 100
        assert report.score_bucket == "Secure"

    def test_perfect_headers_secure(self) -> None:
        findings = [
            Finding(key="csp.present", title="CSP present",
                    severity=Severity.INFO, detail="", weight=0),
            Finding(key="hsts.present", title="HSTS present",
                    severity=Severity.INFO, detail="", weight=0),
        ]
        report = build_report([_make_result(findings)], target="example.com")
        assert report.score_value == 100
        assert report.score_bucket == "Secure"

    def test_missing_hsts_deduction(self) -> None:
        findings = [
            Finding(key="hsts.missing", title="HSTS missing",
                    severity=Severity.MEDIUM, detail="", weight=-15),
        ]
        report = build_report([_make_result(findings)], target="example.com")
        assert report.score_value == 85
        assert report.score_bucket == "Secure"

    def test_expired_cert_risky(self) -> None:
        findings = [
            Finding(key="cert.expired", title="Cert expired",
                    severity=Severity.HIGH, detail="", weight=-40),
            Finding(key="https_missing", title="HTTPS missing",
                    severity=Severity.HIGH, detail="", weight=-30),
        ]
        report = build_report([_make_result(findings)], target="example.com")
        assert report.score_value == 30
        assert report.score_bucket == "Risky"

    def test_multiple_deductions_moderate(self) -> None:
        findings = [
            Finding(key="csp.missing", title="CSP missing",
                    severity=Severity.MEDIUM, detail="", weight=-15),
            Finding(key="x_frame_options.missing", title="XFO missing",
                    severity=Severity.MEDIUM, detail="", weight=-10),
            Finding(key="referrer_policy.missing", title="RP missing",
                    severity=Severity.LOW, detail="", weight=-5),
        ]
        report = build_report([_make_result(findings)], target="example.com")
        assert report.score_value == 70
        assert report.score_bucket == "Moderate"

    def test_score_clamped_at_zero(self) -> None:
        findings = [
            Finding(key="cert.expired", title="Expired",
                    severity=Severity.HIGH, detail="", weight=-40),
            Finding(key="cert.self_signed", title="Self-signed",
                    severity=Severity.HIGH, detail="", weight=-25),
            Finding(key="tls.below_1_2", title="TLS <1.2",
                    severity=Severity.HIGH, detail="", weight=-20),
            Finding(key="https_missing", title="No HTTPS",
                    severity=Severity.HIGH, detail="", weight=-30),
        ]
        report = build_report([_make_result(findings)], target="example.com")
        assert report.score_value == 0

    def test_base_weights_match_prd(self) -> None:
        assert BASE_WEIGHTS["https_missing"] == -30
        assert BASE_WEIGHTS["csp.missing"] == -15
        assert BASE_WEIGHTS["hsts.missing"] == -15
        assert BASE_WEIGHTS["x_frame_options.missing"] == -10
        assert BASE_WEIGHTS["x_content_type_options.missing"] == -5
        assert BASE_WEIGHTS["referrer_policy.missing"] == -5
        assert BASE_WEIGHTS["cert.expired"] == -40
        assert BASE_WEIGHTS["cert.expiring_soon_30d"] == -10
        assert BASE_WEIGHTS["cert.self_signed"] == -25
        assert BASE_WEIGHTS["tls.below_1_2"] == -20
        assert BASE_WEIGHTS["cookie.missing_secure"] == -10
        assert BASE_WEIGHTS["cookie.missing_httponly"] == -10

    def test_report_includes_errors(self) -> None:
        from reconx.core.types import ModuleError
        findings = [Finding(key="csp.missing", title="CSP miss",
                            severity=Severity.MEDIUM, detail="", weight=-15)]
        err = ModuleError(module="ssl_checker", message="timeout", recoverable=True)
        report = build_report([
            _make_result(findings),
            ModuleResult(module_name="ssl_checker", error=err),
        ], target="example.com")
        assert len(report.errors) == 1
        assert report.errors[0].message == "timeout"
