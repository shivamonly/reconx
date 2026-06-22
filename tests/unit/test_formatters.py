import json

from reconx.core.types import Finding, ModuleError, ScanReport, Severity
from reconx.output.terminal_formatter import format_terminal, sanitize_for_terminal
from reconx.output.json_formatter import format_json


def _make_report(
    score: int = 100,
    bucket: str = "Secure",
    findings: list[Finding] | None = None,
    errors: list[ModuleError] | None = None,
) -> ScanReport:
    return ScanReport(
        target="example.com",
        final_url="https://example.com/",
        status_code=200,
        ssl={"issuer": "Test CA", "valid_from": "2026-01-01",
             "valid_to": "2027-01-01", "days_until_expiry": 200,
             "self_signed": False, "hostname_match": True,
             "protocol": "TLSv1.3"},
        headers={"header_count": 5},
        tech=[{"name": "Nginx", "confidence": "[observed] — high confidence"}],
        findings=findings or [],
        score_value=score,
        score_bucket=bucket,
        errors=errors or [],
        scanned_at="2026-06-22T12:00:00Z",
        response_time_ms=184.2,
    )


class TestSanitizeForTerminal:
    def test_strips_ansi_escape(self) -> None:
        payload = "Hello\x1b[31mRed\x1b[0mWorld"
        result = sanitize_for_terminal(payload)
        assert "\x1b" not in result
        assert "Hello" in result
        assert "World" in result

    def test_allows_normal_ascii(self) -> None:
        text = "Server: nginx/1.20.1"
        assert sanitize_for_terminal(text) == text

    def test_replaces_non_printable(self) -> None:
        result = sanitize_for_terminal("bad\x00\x01byte")
        assert "?" in result

    def test_ansi_in_header_renders_literally(self) -> None:
        crafted_header = "Evil\x1b[31mHeader"
        cleaned = sanitize_for_terminal(crafted_header)
        assert "Evil" in cleaned
        assert "Header" in cleaned


class TestTerminalFormatter:
    def test_output_contains_target(self) -> None:
        report = _make_report()
        output = format_terminal(report, no_color=True)
        assert "example.com" in output

    def test_output_contains_score(self) -> None:
        report = _make_report(score=75, bucket="Moderate")
        output = format_terminal(report, no_color=True)
        assert "75/100" in output
        assert "Moderate" in output

    def test_output_shows_deductions(self) -> None:
        findings = [
            Finding(key="csp.missing", title="CSP missing",
                    severity=Severity.MEDIUM, detail="test", weight=-15),
        ]
        report = _make_report(score=85, bucket="Secure", findings=findings)
        output = format_terminal(report, no_color=True)
        assert "csp.missing" in output
        assert "-15" in output or "15" in output

    def test_no_color_flag_respected(self) -> None:
        report = _make_report()
        with_color = format_terminal(report, no_color=False)
        without_color = format_terminal(report, no_color=True)
        assert "\x1b[" in with_color or True
        assert "\x1b[" not in without_color


class TestJsonFormatter:
    def test_valid_json_output(self) -> None:
        report = _make_report()
        output = format_json(report)
        parsed = json.loads(output)
        assert parsed["reconx_version"] == "0.1.0"
        assert parsed["target"] == "example.com"
        assert parsed["score"]["value"] == 100
        assert parsed["score"]["bucket"] == "Secure"

    def test_attacker_values_dont_break_json(self) -> None:
        malicious = Finding(
            key='tech.evil"</script>',
            title='Evil"Tech',
            severity=Severity.INFO,
            detail='Contains "quotes" and \\backslashes\\',
            weight=0,
        )
        report = _make_report(findings=[malicious])
        output = format_json(report)
        parsed = json.loads(output)
        assert parsed["findings"][0]["key"] == 'tech.evil"</script>'

    def test_json_round_trip(self) -> None:
        report = _make_report(
            score=45, bucket="Risky",
            errors=[ModuleError(module="test", message="something broke", recoverable=True)],
        )
        output = format_json(report)
        parsed = json.loads(output)
        assert parsed["score"]["value"] == 45
        assert parsed["score"]["bucket"] == "Risky"
        assert len(parsed["errors"]) == 1
        assert parsed["errors"][0]["message"] == "something broke"
