import ipaddress
import socket
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from reconx.core.module_base import ReconModule
from reconx.core.types import Finding, ModuleError, ModuleResult, ScanConfig, Severity


class MaxRedirectsError(requests.RequestException):
    pass


class URLChecker(ReconModule):
    name = "url_checker"

    def run(self, config: ScanConfig, shared_context: dict[str, Any]) -> ModuleResult:
        start_time = time.monotonic()
        findings: list[Finding] = []
        redirect_chain: list[dict[str, Any]] = []
        resolved_ip: str | None = None
        dns_ms: float = 0.0

        try:
            target = config.target.strip()
            original_parsed = urlparse(target)
            is_bare_domain = not original_parsed.scheme

            if not is_bare_domain and original_parsed.scheme not in ("http", "https"):
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name,
                        f"Unsupported URL scheme: {original_parsed.scheme} (use http or https)",
                        recoverable=False,
                    ),
                )

            target = "https://" + target if is_bare_domain else target
            parsed = urlparse(target)
            hostname = parsed.hostname
            if not hostname:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name, f"Could not parse hostname: {config.target}", recoverable=False,
                    ),
                )

            port = parsed.port or 443

            dns_start = time.monotonic()
            try:
                addrs = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except socket.gaierror as exc:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name,
                        f"DNS resolution failed for {hostname}: {exc}",
                        recoverable=False,
                    ),
                )
            dns_ms = (time.monotonic() - dns_start) * 1000

            for fam, _typ, _proto, _cn, sa in addrs:
                if fam in (socket.AF_INET, socket.AF_INET6) and sa:
                    addr = str(sa[0])
                    resolved_ip = addr
                    break

            if not resolved_ip:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name, f"No address records found for {hostname}", recoverable=False,
                    ),
                )

            ip_obj = ipaddress.ip_address(resolved_ip)
            is_restricted = (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
            )
            if not config.allow_private_targets and is_restricted:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name,
                        f"Target resolves to a private/reserved address ({resolved_ip}). "
                        "Use --allow-private-targets to override.",
                        recoverable=False,
                    ),
                )

            session = requests.Session()
            session.verify = True
            session.headers["User-Agent"] = config.user_agent

            urls_to_try: list[str] = [target]
            http_fallback = False
            if is_bare_domain:
                http_url = target.replace("https://", "http://", 1)
                urls_to_try.append(http_url)

            last_exception: Exception | None = None
            final_response: requests.Response | None = None
            body_bytes = b""

            for attempt_url in urls_to_try:
                try:
                    result = self._fetch_with_redirects(session, attempt_url, config)
                    if result is None:
                        raise MaxRedirectsError(
                            f"Redirect limit of {config.max_redirects} exceeded"
                        )
                    final_response, redirect_chain, body_bytes = result
                    if attempt_url.startswith("http://") and target.startswith("https://"):
                        http_fallback = True
                    last_exception = None
                    break
                except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as exc:
                    last_exception = exc
                    continue

            if final_response is None:
                err_msg = (
                    str(last_exception) if last_exception else "All connection attempts failed"
                )
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(self.name, err_msg, recoverable=True),
                )

            total_ms = (time.monotonic() - start_time) * 1000
            final_url = final_response.url

            if final_url.startswith("http://"):
                findings.append(Finding(
                    key="https_missing",
                    title="HTTPS not enforced",
                    severity=Severity.HIGH,
                    detail=(
                        "The final URL uses plain HTTP instead of HTTPS. "
                        "All traffic is sent in cleartext and can be intercepted by "
                        "any attacker on the network path."
                    ),
                    weight=-30,
                ))

            if http_fallback:
                findings.append(Finding(
                    key="https_fallback",
                    title="HTTPS connection failed, fell back to HTTP",
                    severity=Severity.HIGH,
                    detail=(
                        f"Initial HTTPS connection to {hostname} failed. "
                        "The server may not support HTTPS or may have a TLS issue. "
                        "The scan proceeded over unencrypted HTTP."
                    ),
                    weight=-30,
                ))

            if len(redirect_chain) == config.max_redirects:
                findings.append(Finding(
                    key="redirect_limit_reached",
                    title="Redirect limit reached",
                    severity=Severity.INFO,
                    detail=(
                        f"The server issued {config.max_redirects} redirects. "
                        "The final response may not be the intended destination."
                    ),
                    weight=0,
                ))

            shared_context["resolved_ip"] = resolved_ip
            shared_context["redirect_chain"] = redirect_chain
            shared_context["final_url"] = final_url
            shared_context["status_code"] = final_response.status_code
            shared_context["response_headers"] = dict(final_response.headers)
            shared_context["response_body"] = body_bytes

            raw: dict[str, Any] = {
                "resolved_ip": resolved_ip,
                "final_url": final_url,
                "status_code": final_response.status_code,
                "response_time_ms": total_ms,
                "dns_ms": dns_ms,
                "redirect_chain": redirect_chain,
            }

            return ModuleResult(
                module_name=self.name,
                findings=findings,
                raw=raw,
                duration_ms=total_ms,
            )

        except MaxRedirectsError as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, str(exc), recoverable=True),
            )
        except requests.RequestException as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, str(exc), recoverable=True),
            )
        except TimeoutError as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, f"Connection timed out: {exc}", recoverable=True),
            )
        except Exception as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, f"Unexpected error: {exc}", recoverable=False),
            )

    @staticmethod
    def _read_body(response: requests.Response, max_bytes: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            remaining = max_bytes - total
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            total += min(len(chunk), remaining)
        return b"".join(chunks)

    @staticmethod
    def _fetch_with_redirects(
        session: requests.Session,
        url: str,
        config: ScanConfig,
    ) -> tuple[requests.Response, list[dict[str, Any]], bytes] | None:
        redirect_chain: list[dict[str, Any]] = []
        current_url = url

        for hop in range(config.max_redirects + 1):
            resp = session.get(
                current_url,
                stream=True,
                timeout=config.timeout,
                allow_redirects=False,
            )

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    body = URLChecker._read_body(resp, config.max_body_bytes)
                    return resp, redirect_chain, body
                redirect_chain.append({"status": resp.status_code, "location": location})
                current_url = urljoin(current_url, location)
                resp.close()
                continue

            body = URLChecker._read_body(resp, config.max_body_bytes)
            return resp, redirect_chain, body

        return None
