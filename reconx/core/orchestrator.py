import time
from typing import Any

from reconx.core.module_base import ReconModule
from reconx.core.score_engine import build_report
from reconx.core.types import ModuleResult, ScanConfig, ScanReport


def select_modules(config: ScanConfig) -> list[ReconModule]:
    from reconx.modules.header_analyzer import HeaderAnalyzer
    from reconx.modules.ssl_checker import SSLChecker
    from reconx.modules.tech_detector import TechDetector
    from reconx.modules.url_checker import URLChecker

    modules: list[ReconModule] = []

    if config.headers_only:
        modules.append(URLChecker())
        modules.append(HeaderAnalyzer())
    elif config.ssl_only:
        from reconx.modules.url_checker import URLChecker
        modules.append(URLChecker())
        modules.append(SSLChecker())
    elif config.tech_only:
        modules.append(URLChecker())
        modules.append(TechDetector())
    else:
        modules.append(URLChecker())
        modules.append(HeaderAnalyzer())
        modules.append(SSLChecker())
        modules.append(TechDetector())

    return modules


def run_scan(config: ScanConfig) -> ScanReport:
    shared_context: dict[str, Any] = {}
    results: list[ModuleResult] = []

    modules = select_modules(config)

    for module in modules:
        start = time.monotonic()
        try:
            result = module.run(config, shared_context)
        except Exception as exc:
            result = ModuleResult(
                module_name=module.name,
                error=_make_error(module.name, str(exc), recoverable=True),
                duration_ms=(time.monotonic() - start) * 1000,
            )
        results.append(result)

    return build_report(results, target=config.target)


def _make_error(module: str, message: str, recoverable: bool) -> Any:
    from reconx.core.types import ModuleError
    return ModuleError(module=module, message=message, recoverable=recoverable)
