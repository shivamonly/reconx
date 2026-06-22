import os
import socket
import ssl
import threading
import time
from typing import Any

import pytest
import trustme

from reconx.core.types import ScanConfig
from reconx.modules.ssl_checker import SSLChecker


def _run_tls_server(host: str, port: int, cert_pem: bytes, key_pem: bytes,
                    results: list[Any]) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_path = os.path.join(os.path.dirname(__file__), "_test_srv_cert.pem")
    key_path = os.path.join(os.path.dirname(__file__), "_test_srv_key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)
    ctx.load_cert_chain(cert_path, key_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    sock.settimeout(5.0)

    results.append(("ready", sock.getsockname()[1]))

    try:
        conn, addr = sock.accept()
        tls_conn = ctx.wrap_socket(conn, server_side=True)
        data = tls_conn.recv(1024)
        tls_conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        tls_conn.close()
        conn.close()
    except Exception as e:
        results.append(("error", str(e)))
    finally:
        sock.close()
        try:
            os.unlink(cert_path)
        except Exception:
            pass
        try:
            os.unlink(key_path)
        except Exception:
            pass


@pytest.fixture
def tls_server():
    results: list[Any] = []
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1")
    cert_pem = b"".join(c.bytes() for c in server_cert.cert_chain_pems) + b"\n" + ca.cert_pem.bytes()
    key_pem = server_cert.private_key_pem.bytes()

    t = threading.Thread(
        target=_run_tls_server,
        args=("127.0.0.1", 0, cert_pem, key_pem, results),
        daemon=True,
    )
    t.start()
    timeout = 5.0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(r[0] == "ready" for r in results):
            for r in results:
                if r[0] == "ready":
                    yield r[1]
                    return
        time.sleep(0.05)
    pytest.fail("TLS server did not start")


class TestSSLCheckerValid:
    def test_valid_cert(self, tls_server: int) -> None:
        port = tls_server
        checker = SSLChecker()
        config = ScanConfig(
            target=f"https://127.0.0.1:{port}",
            allow_private_targets=True,
            timeout=3.0,
        )
        ctx: dict[str, Any] = {"resolved_ip": "127.0.0.1"}
        result = checker.run(config, ctx)

        assert result.error is None, f"Unexpected error: {result.error}"
        assert result.raw.get("protocol", "") != ""
        assert "valid_from" in result.raw
        assert "valid_to" in result.raw


class TestSSLCheckerErrors:
    def test_connection_timeout(self) -> None:
        checker = SSLChecker()
        config = ScanConfig(
            target="https://192.0.2.1",
            timeout=0.1,
        )
        ctx: dict[str, Any] = {"resolved_ip": "192.0.2.1"}
        result = checker.run(config, ctx)
        assert result.error is not None
