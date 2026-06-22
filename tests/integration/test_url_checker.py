import socket
import threading
import time
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from reconx.core.types import ScanConfig
from reconx.modules.url_checker import URLChecker


class MockReconHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server: Any = self.server
        cfg: dict[str, Any] = server._mock_config
        redirects: list[dict[str, Any]] = cfg.get("redirects", [])
        path = self.path

        for rd in redirects:
            if rd.get("from", "/") == path:
                self.send_response(rd.get("status", 302))
                location = rd["to"]
                self.send_header("Location", location)
                self.end_headers()
                return

        self.send_response(cfg.get("status", 200))
        for k, v in cfg.get("headers", {}).items():
            self.send_header(k, v)
        body: bytes = cfg.get("body", b"OK")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass


@pytest.fixture
def mock_server() -> Generator[tuple[Any, int], None, None]:
    server: Any = HTTPServer(("127.0.0.1", 0), MockReconHandler)
    server._mock_config = {}
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield server, port
    server.shutdown()


class TestURLCheckerNormal:
    def test_normal_200(self, mock_server: tuple[Any, int]) -> None:
        server, port = mock_server
        server._mock_config = {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": b"<html><body>OK</body></html>",
        }

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
        )
        ctx: dict[str, Any] = {}
        result = checker.run(config, ctx)

        assert result.error is None
        assert result.raw["status_code"] == 200
        assert result.raw["final_url"] == f"http://127.0.0.1:{port}/"
        assert ctx["resolved_ip"] == "127.0.0.1"
        assert ctx["response_body"] == b"<html><body>OK</body></html>"
        assert ctx["response_headers"]["Content-Type"] == "text/html"

    def test_duration_ms_is_set(self, mock_server: tuple[Any, int]) -> None:
        server, port = mock_server
        server._mock_config = {"status": 200, "body": b"hello"}

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
        )
        result = checker.run(config, {})

        assert result.error is None
        assert result.duration_ms > 0
        assert result.raw["response_time_ms"] > 0
        assert result.raw["dns_ms"] >= 0


class TestURLCheckerDNSFailure:
    def test_dns_failure_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def mock_getaddrinfo(
            host: str,
            port: int,
            family: int = 0,
            socktype: int = 0,
            proto: int = 0,
            flags: int = 0,
        ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            msg = f"getaddrinfo failed for {host}"
            raise socket.gaierror(11001, msg)

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        checker = URLChecker()
        config = ScanConfig(target="http://nonexistent.invalid")
        result = checker.run(config, {})

        assert result.error is not None
        assert not result.error.recoverable
        assert "DNS resolution failed" in result.error.message


class TestURLCheckerSSRF:
    def test_private_ip_blocked_by_default(self) -> None:
        checker = URLChecker()
        config = ScanConfig(target="http://127.0.0.1:1/")
        result = checker.run(config, {})

        assert result.error is not None
        msg = result.error.message.lower()
        assert "private" in msg or "reserved" in msg or "loopback" in msg

    def test_private_ip_allowed_with_flag(self, mock_server: tuple[Any, int]) -> None:
        server, port = mock_server
        server._mock_config = {"status": 200, "body": b"OK"}

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
        )
        result = checker.run(config, {})

        assert result.error is None
        assert result.raw["status_code"] == 200


class TestURLCheckerRedirects:
    def test_single_redirect_followed(self, mock_server: tuple[Any, int]) -> None:
        server, port = mock_server
        server._mock_config = {
            "redirects": [{"from": "/", "to": "/final", "status": 302}],
            "status": 200,
            "body": b"redirected",
        }

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
        )
        ctx: dict[str, Any] = {}
        result = checker.run(config, ctx)

        assert result.error is None
        assert result.raw["status_code"] == 200
        assert result.raw["final_url"] == f"http://127.0.0.1:{port}/final"
        assert len(result.raw["redirect_chain"]) == 1
        assert result.raw["redirect_chain"][0]["status"] == 302
        assert ctx["response_body"] == b"redirected"
        assert ctx["final_url"] == f"http://127.0.0.1:{port}/final"

    def test_multiple_redirects(self, mock_server: tuple[Any, int]) -> None:
        server, port = mock_server
        server._mock_config = {
            "redirects": [
                {"from": "/", "to": "/a", "status": 301},
                {"from": "/a", "to": "/b", "status": 302},
                {"from": "/b", "to": "/c", "status": 307},
            ],
            "status": 200,
            "body": b"triple redirect",
        }

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
        )
        ctx: dict[str, Any] = {}
        result = checker.run(config, ctx)

        assert result.error is None
        assert result.raw["status_code"] == 200
        assert len(result.raw["redirect_chain"]) == 3
        assert ctx["response_body"] == b"triple redirect"

    def test_redirect_limit_exceeded(self, mock_server: tuple[Any, int]) -> None:
        server, port = mock_server
        redirects = [
            {"from": "/", "to": "/a", "status": 302},
            {"from": "/a", "to": "/b", "status": 302},
            {"from": "/b", "to": "/c", "status": 302},
            {"from": "/c", "to": "/d", "status": 302},
            {"from": "/d", "to": "/e", "status": 302},
            {"from": "/e", "to": "/f", "status": 302},
        ]
        server._mock_config = {"redirects": redirects}

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
            max_redirects=5,
        )
        result = checker.run(config, {})

        assert result.error is not None
        assert "redirect" in result.error.message.lower()
        assert "limit" in result.error.message.lower()

    def test_redirect_with_no_location_treated_as_final(
        self, mock_server: tuple[Any, int]
    ) -> None:
        server, port = mock_server

        class NoLocationHandler(MockReconHandler):
            def do_GET(self) -> None:
                srv: Any = self.server
                cfg = srv._mock_config
                path = self.path
                for rd in cfg.get("redirects", []):
                    if rd["from"] == path:
                        self.send_response(302)
                        self.end_headers()
                        return
                self.send_response(200)
                body = cfg.get("body", b"")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        original_handler = server.RequestHandlerClass
        server.RequestHandlerClass = NoLocationHandler
        server._mock_config = {
            "redirects": [{"from": "/", "to": "", "status": 302}],
            "status": 200,
            "body": b"no location",
        }

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
            max_redirects=5,
        )
        result = checker.run(config, {})
        server.RequestHandlerClass = original_handler

        assert result.error is None
        assert result.raw["status_code"] == 302


class TestURLCheckerBodyTruncation:
    def test_large_body_truncated(self, mock_server: tuple[Any, int]) -> None:
        server, port = mock_server
        large_body = b"X" * 2_500_000
        server._mock_config = {
            "status": 200,
            "body": large_body,
            "headers": {"Content-Length": str(len(large_body))},
        }

        checker = URLChecker()
        config = ScanConfig(
            target=f"http://127.0.0.1:{port}/",
            allow_private_targets=True,
            max_body_bytes=1_000_000,
        )
        ctx: dict[str, Any] = {}
        result = checker.run(config, ctx)

        assert result.error is None
        assert len(ctx["response_body"]) == 1_000_000
        assert ctx["response_body"] == b"X" * 1_000_000


class TestURLCheckerHTTPFallback:
    def test_bare_domain_https_fallback_to_http(
        self, mock_server: tuple[Any, int]
    ) -> None:
        server, port = mock_server
        server._mock_config = {"status": 200, "body": b"OK"}

        checker = URLChecker()
        config = ScanConfig(
            target=f"127.0.0.1:{port}",
            allow_private_targets=True,
        )
        result = checker.run(config, {})

        assert result.error is None
        assert result.raw["status_code"] == 200

    def test_http_fallback_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ])

        import requests
        original_get = requests.Session.get

        call_count = 0

        def mock_get(
            self: requests.Session, url: str, **kwargs: Any
        ) -> requests.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1 and url.startswith("https://"):
                raise requests.exceptions.SSLError("SSL handshake failed")
            return original_get(self, url, **kwargs)

        monkeypatch.setattr(requests.Session, "get", mock_get)

        checker = URLChecker()
        config = ScanConfig(target="example.com")
        result = checker.run(config, {})

        assert result.error is not None
