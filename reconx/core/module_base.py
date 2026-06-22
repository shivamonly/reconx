from abc import ABC, abstractmethod
from typing import Any

from reconx.core.types import ModuleResult, ScanConfig


class ReconModule(ABC):
    """
    Every scan module (URLChecker, HeaderAnalyzer, SSLChecker, TechDetector)
    implements this contract. The orchestrator only ever talks to this
    interface — it never knows module internals.

    CONTRACT:
    - `run()` MUST NOT raise. All exceptions are caught internally and
      surfaced as `ModuleResult.error`.
    - `run()` MUST respect `config.timeout` for every network operation
      it performs, with no exceptions.
    - `run()` MUST NOT perform more than one network round-trip per
      "check" it claims to do, unless explicitly documented (keeps the
      tool fast and keeps it auditable as "passive").
    """

    name: str

    @abstractmethod
    def run(self, config: ScanConfig, shared_context: dict[str, Any]) -> ModuleResult:
        """
        `shared_context` carries data already fetched by earlier modules
        (e.g. the resolved IP, the already-fetched response object) so we
        never issue duplicate requests to the target for the same scan.
        """
        raise NotImplementedError
