from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ScanConfig:
    target: str
    timeout: float = 5.0
    max_redirects: int = 5
    max_body_bytes: int = 2_000_000
    user_agent: str = "ReconX/1.0 (+https://github.com/<org>/reconx)"
    allow_private_targets: bool = False
    verbose: bool = False
    headers_only: bool = False
    ssl_only: bool = False
    tech_only: bool = False
    json_output: bool = False
    no_color: bool = False


@dataclass(frozen=True)
class Finding:
    key: str
    title: str
    severity: Severity
    detail: str
    weight: int


@dataclass(frozen=True)
class ModuleError:
    module: str
    message: str
    recoverable: bool


@dataclass(frozen=True)
class ModuleResult:
    module_name: str
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: ModuleError | None = None
    duration_ms: float = 0.0


@dataclass(frozen=True)
class ScanReport:
    target: str
    final_url: str | None
    status_code: int | None
    ssl: dict[str, Any]
    headers: dict[str, Any]
    tech: list[dict[str, Any]]
    findings: list[Finding]
    score_value: int
    score_bucket: str
    errors: list[ModuleError]
    scanned_at: str
    response_time_ms: float
    reconx_version: str = "0.1.0"
