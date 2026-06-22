import datetime as dt
import socket
import ssl
import time
from datetime import timezone
from typing import Any

from reconx.core.module_base import ReconModule
from reconx.core.types import Finding, ModuleError, ModuleResult, ScanConfig, Severity


class SSLChecker(ReconModule):
    name = "ssl_checker"

    def run(self, config: ScanConfig, shared_context: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        raw: dict[str, Any] = {}

        try:
            hostname = shared_context.get("resolved_ip")
            if not hostname:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name,
                        "No resolved IP available (run url_checker first)",
                        recoverable=True,
                    ),
                )

            parsed_target = config.target.strip()
            if "://" in parsed_target:
                parsed_target = parsed_target.split("://", 1)[1]
            port = 443
            if ":" in parsed_target.split("/")[0]:
                host_part, port_str = parsed_target.split("/")[0].split(":", 1)
                parsed_target = host_part
                port = int(port_str.split("/")[0])
            else:
                parsed_target = parsed_target.split("/")[0]

            # Per PRD 7.4: Use CERT_NONE to retrieve the presented certificate
            # for inspection without requiring a trusted chain. The content-
            # fetching path (url_checker) always uses verify=True.
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection(
                (hostname, port),
                timeout=config.timeout,
            )

            with context.wrap_socket(sock, server_hostname=parsed_target) as tls:
                tls.settimeout(config.timeout)
                cert_bin = tls.getpeercert(binary_form=True)
                protocol = tls.version() or "unknown"

            raw["protocol"] = protocol
            raw["hostname_checked"] = parsed_target

            if cert_bin is None:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name, "No certificate presented by server", recoverable=True,
                    ),
                )

            crypto_cert = _load_certificate(cert_bin)
            if crypto_cert is None:
                return ModuleResult(
                    module_name=self.name,
                    error=ModuleError(
                        self.name, "Failed to parse certificate", recoverable=True,
                    ),
                )

            subject_cn = _crypto_get_cn(crypto_cert.subject)
            issuer_cn = _crypto_get_cn(crypto_cert.issuer)
            raw["issuer"] = issuer_cn
            raw["subject"] = subject_cn

            valid_from = crypto_cert.not_valid_before_utc
            valid_to = crypto_cert.not_valid_after_utc
            raw["valid_from"] = valid_from.isoformat()
            raw["valid_to"] = valid_to.isoformat()

            days_until = (valid_to - dt.datetime.now(timezone.utc)).days
            raw["days_until_expiry"] = days_until

            if days_until < 0:
                findings.append(Finding(
                    key="cert.expired",
                    title="TLS certificate is expired",
                    severity=Severity.HIGH,
                    detail=f"Certificate expired on {valid_to.isoformat()}.",
                    weight=-40,
                ))
            elif days_until <= 30:
                findings.append(Finding(
                    key="cert.expiring_soon_30d",
                    title="TLS certificate expiring within 30 days",
                    severity=Severity.MEDIUM,
                    detail=f"Certificate expires in {days_until} days (on {valid_to.isoformat()}).",
                    weight=-10,
                ))

            self_signed = subject_cn == issuer_cn
            raw["self_signed"] = self_signed
            if self_signed:
                findings.append(Finding(
                    key="cert.self_signed",
                    title="TLS certificate is self-signed",
                    severity=Severity.HIGH,
                    detail=(
                        "Self-signed certificates are not trusted by browsers. "
                        "They may indicate a test environment or a MITM proxy."
                    ),
                    weight=-25,
                ))

            sans = _crypto_get_sans(crypto_cert)
            raw["sans"] = sans

            hostname_match = _check_hostname(parsed_target, sans)
            raw["hostname_match"] = hostname_match
            if not hostname_match:
                findings.append(Finding(
                    key="cert.hostname_mismatch",
                    title="Certificate hostname mismatch",
                    severity=Severity.HIGH,
                    detail=(
                        f"Certificate is not valid for {parsed_target}. "
                        f"SANs: {', '.join(sans) if sans else subject_cn}."
                    ),
                    weight=-25,
                ))

            if protocol in ("TLSv1", "TLSv1.1"):
                findings.append(Finding(
                    key="tls.below_1_2",
                    title="TLS version below 1.2",
                    severity=Severity.HIGH,
                    detail=(
                        f"Server negotiated {protocol}, which is deprecated. "
                        "TLS 1.2 or higher is required for secure communications."
                    ),
                    weight=-20,
                ))

            shared_context["ssl_cert"] = crypto_cert
            shared_context["ssl_protocol"] = protocol
            shared_context["ssl_self_signed"] = self_signed
            shared_context["ssl_hostname_match"] = hostname_match

            return ModuleResult(
                module_name=self.name,
                findings=findings,
                raw=raw,
                duration_ms=(time.monotonic() - start) * 1000,
            )

        except TimeoutError as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, f"TLS connection timed out: {exc}", recoverable=True),
            )
        except socket.gaierror as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(
                    self.name, f"DNS resolution failed for TLS: {exc}", recoverable=False,
                ),
            )
        except ConnectionRefusedError as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, f"TLS connection refused: {exc}", recoverable=True),
            )
        except OSError as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, f"TLS connection error: {exc}", recoverable=True),
            )
        except Exception as exc:
            return ModuleResult(
                module_name=self.name,
                error=ModuleError(self.name, f"Unexpected TLS error: {exc}", recoverable=False),
            )


def _load_certificate(cert_bin: bytes) -> Any:
    try:
        from cryptography import x509
        return x509.load_der_x509_certificate(cert_bin)
    except Exception:
        return None


def _crypto_get_cn(name: Any) -> str:
    try:
        for attr in name:
            if attr.oid._name == "commonName":
                return str(attr.value)
    except Exception:
        pass
    try:
        result: str = name.rfc4514_string()
        return result
    except Exception:
        return ""


def _crypto_get_sans(crypto_cert: Any) -> list[str]:
    try:
        from cryptography.x509.extensions import SubjectAlternativeName
        ext = crypto_cert.extensions.get_extension_for_class(SubjectAlternativeName)
        return [str(name.value) for name in ext.value]
    except Exception:
        return []


def _check_hostname(hostname: str, sans: list[str]) -> bool:
    hostname = hostname.lower()
    for san in sans:
        san = san.lower()
        if san.startswith("*."):
            domain_part = san[2:]
            if hostname == domain_part or hostname.endswith("." + domain_part):
                return True
        elif san == hostname:
            return True
    return False
