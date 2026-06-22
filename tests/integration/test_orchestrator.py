import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

import pytest

from reconx.core.orchestrator import run_scan, select_modules
from reconx.core.types import ScanConfig


class SingleRequestHandler(BaseHTTPRequestHandler):
    request_count = 0

    def do_GET(self) -> None:
        type(self).request_count += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        body = b"<html>OK</html>"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass


@pytest.fixture
def single_request_server():
    SingleRequestHandler.request_count = 0
    server = HTTPServer(("127.0.0.1", 0), SingleRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield server, port
    server.shutdown()


class TestSelectModules:
    def test_default_all_modules(self) -> None:
        config = ScanConfig(target="example.com")
        modules = select_modules(config)
        names = [m.name for m in modules]
        assert names == ["url_checker", "header_analyzer", "ssl_checker", "tech_detector"]

    def test_headers_only(self) -> None:
        config = ScanConfig(target="example.com", headers_only=True)
        modules = select_modules(config)
        names = [m.name for m in modules]
        assert names == ["url_checker", "header_analyzer"]

    def test_ssl_only(self) -> None:
        config = ScanConfig(target="example.com", ssl_only=True)
        modules = select_modules(config)
        names = [m.name for m in modules]
        assert "ssl_checker" in names
        assert "header_analyzer" not in names

    def test_tech_only(self) -> None:
        config = ScanConfig(target="example.com", tech_only=True)
        modules = select_modules(config)
        names = [m.name for m in modules]
        assert names == ["url_checker", "tech_detector"]


class TestRunScan:
    def test_full_scan(self, single_request_server: Any) -> None:
        server, port = single_request_server
        config = ScanConfig(
            target=f"127.0.0.1:{port}",
            allow_private_targets=True,
        )
        report = run_scan(config)

        assert report.status_code == 200
        assert report.score_value >= 0
        assert report.score_bucket in ("Secure", "Moderate", "Risky")
        assert report.errors is not None
        assert report.response_time_ms > 0

    def test_single_fetch_reused(self, single_request_server: Any) -> None:
        server, port = single_request_server
        SingleRequestHandler.request_count = 0

        config = ScanConfig(
            target=f"127.0.0.1:{port}",
            allow_private_targets=True,
        )
        run_scan(config)

        assert SingleRequestHandler.request_count == 1

    def test_headers_only_scan(self, single_request_server: Any) -> None:
        server, port = single_request_server
        config = ScanConfig(
            target=f"127.0.0.1:{port}",
            allow_private_targets=True,
            headers_only=True,
        )
        report = run_scan(config)
        assert report.status_code == 200

    def test_scan_error_handling(self) -> None:
        config = ScanConfig(
            target="nonexistent-domain-12345.invalid",
            timeout=0.5,
        )
        report = run_scan(config)
        assert len(report.errors) > 0
