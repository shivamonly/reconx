import json
import subprocess
import sys
from pathlib import Path

import pytest

from reconx.cli import parse_args


class TestCliArgs:
    def test_scan_command_required(self) -> None:
        args = parse_args([])
        assert args.command is None

    def test_scan_without_target_sets_empty(self) -> None:
        args = parse_args(["scan"])
        assert args.target == ""

    def test_scan_basic(self) -> None:
        args = parse_args(["scan", "example.com"])
        assert args.target == "example.com"

    def test_scan_with_scheme(self) -> None:
        args = parse_args(["scan", "https://example.com"])
        assert args.target == "https://example.com"

    def test_headers_flag(self) -> None:
        args = parse_args(["scan", "example.com", "--headers"])
        assert args.headers is True

    def test_ssl_flag(self) -> None:
        args = parse_args(["scan", "example.com", "--ssl"])
        assert args.ssl is True
        assert args.headers is False

    def test_tech_flag(self) -> None:
        args = parse_args(["scan", "example.com", "--tech"])
        assert args.tech is True

    def test_json_flag(self) -> None:
        args = parse_args(["scan", "example.com", "--json"])
        assert args.json is True

    def test_timeout_flag(self) -> None:
        args = parse_args(["scan", "example.com", "--timeout", "10"])
        assert args.timeout == 10.0

    def test_no_color_flag(self) -> None:
        args = parse_args(["scan", "example.com", "--no-color"])
        assert args.no_color is True

    def test_verbose_flag(self) -> None:
        args = parse_args(["scan", "example.com", "--verbose"])
        assert args.verbose is True
        args2 = parse_args(["scan", "example.com", "-v"])
        assert args2.verbose is True

    def test_empty_target_allowed_as_optional(self) -> None:
        args = parse_args(["scan", ""])
        assert args.target == ""

    def test_rejects_control_chars(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["scan", "example.com\x00"])

    def test_allow_private_targets(self) -> None:
        args = parse_args(["scan", "example.com", "--allow-private-targets"])
        assert args.allow_private_targets is True


class TestCliE2E:
    def test_scan_live_with_json(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "reconx", "scan", "example.com", "--json",
             "--timeout", "10", "--no-color"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        parsed = json.loads(result.stdout)
        assert parsed["target"] == "example.com"
        assert "score" in parsed

    def test_scan_live_terminal(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "reconx", "scan", "example.com",
             "--timeout", "10", "--no-color"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "example.com" in result.stdout
        assert "Score" in result.stdout or "Security" in result.stdout

    def test_version_flag(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "reconx", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 0
        assert "0.1.0" in result.stdout
