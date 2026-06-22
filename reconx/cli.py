import argparse
import re
import sys

from reconx import __version__
from reconx.core.orchestrator import run_scan
from reconx.core.types import ScanConfig
from reconx.output.json_formatter import format_json
from reconx.output.terminal_formatter import format_terminal


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX - Terminal-Based Web Reconnaissance & Security Analyzer",
        epilog=(
            "ReconX performs passive analysis only. You are responsible for ensuring "
            "you have the right to scan any target you specify."
        ),
        add_help=False,
    )
    parser.add_argument("--version", action="version", version=f"reconx {__version__}",
                        help="Print version and exit")
    parser.add_argument("--help", action="help", help="Show this help message and exit")

    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", help="Scan a target domain or URL")

    scan_parser.add_argument("target", nargs="?", default="", help="Domain or URL to scan")

    mode = scan_parser.add_mutually_exclusive_group()
    mode.add_argument("--headers", action="store_true", help="Run header analysis only")
    mode.add_argument("--ssl", action="store_true", help="Run SSL/TLS analysis only")
    mode.add_argument("--tech", action="store_true", help="Run tech detection only")
    mode.add_argument("--all", action="store_true", help="Run all checks (default)")

    scan_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    scan_parser.add_argument("--timeout", type=float, default=5.0,
                             help="Request timeout in seconds (default: 5)")
    scan_parser.add_argument("--no-color", action="store_true",
                             help="Disable ANSI color output")
    scan_parser.add_argument("--verbose", "-v", action="store_true",
                             help="Show request/response metadata")
    scan_parser.add_argument("--allow-private-targets", action="store_true",
                             help="Allow scanning private IP ranges")

    args = parser.parse_args(argv)

    if args.command == "scan":
        if args.target and re.search(r"[\s\x00-\x1f]", args.target):
            parser.error("target contains invalid characters (spaces or control characters)")

    return args


def _run_scan_for_target(target: str, no_color: bool = False, json_output: bool = False,
                         timeout: float = 5.0) -> int:
    config = ScanConfig(
        target=target.strip(),
        timeout=timeout,
        allow_private_targets=False,
        verbose=False,
        headers_only=False,
        ssl_only=False,
        tech_only=False,
        json_output=json_output,
        no_color=no_color,
    )
    report = run_scan(config)
    if json_output:
        print(format_json(report))
    else:
        print(format_terminal(report, no_color=no_color))
    return 0


def _show_menu() -> int:
    while True:
        print("")
        print("  ReconX - Web Reconnaissance & Security Analyzer")
        print(f"  v{__version__}  |  Passive analysis only")
        print("")
        print("  [1]  Enter a target URL to scan")
        print("  [2]  Help / About")
        print("  [3]  Exit")
        print("")
        choice = input("  Select an option [1-3]: ").strip()

        if choice == "1":
            target = input("  Target domain or URL: ").strip()
            if not target:
                print("  [!] No target entered.")
                continue
            return _run_scan_for_target(target)

        elif choice == "2":
            print("")
            print("  ReconX - Terminal-Based Web Reconnaissance & Security Analyzer")
            print("  Version:", __version__)
            print("  License: MIT")
            print("")
            print("  What it does:")
            print("    - URL resolution and redirect analysis")
            print("    - DNS and SSRF guard checks")
            print("    - TLS/SSL certificate inspection")
            print("    - Security header analysis (CSP, HSTS, etc.)")
            print("    - Technology stack detection")
            print("    - Security scoring with weighted findings")
            print("")
            print("  Quick usage:")
            print("    reconx scan example.com")
            print("    reconx scan example.com --json")
            print("    reconx scan https://example.com --ssl --headers")
            print("    reconx --version")
            print("")
            print("  Flags:")
            print("    --headers              Header analysis only")
            print("    --ssl                  SSL/TLS analysis only")
            print("    --tech                 Tech detection only")
            print("    --json                 JSON output")
            print("    --timeout <sec>        Request timeout (default: 5)")
            print("    --no-color             Disable ANSI colors")
            print("    --verbose, -v          Show request/response metadata")
            print("    --allow-private-targets  Allow scanning private IPs")
            print("")
            print("  Responsible use:")
            print("    Only scan targets you own or have permission to test.")
            input("  Press Enter to continue...")

        elif choice == "3":
            print("  Goodbye.")
            return 0

        else:
            print("  [!] Invalid option. Choose 1-3.")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.command != "scan":
        return _show_menu()

    target = args.target.strip() if args.target else ""
    if not target:
        return _show_menu()

    if args.all or not (args.headers or args.ssl or args.tech):
        headers_only = False
        ssl_only = False
        tech_only = False
    else:
        headers_only = args.headers
        ssl_only = args.ssl
        tech_only = args.tech

    config = ScanConfig(
        target=target,
        timeout=args.timeout,
        allow_private_targets=args.allow_private_targets,
        verbose=args.verbose,
        headers_only=headers_only,
        ssl_only=ssl_only,
        tech_only=tech_only,
        json_output=args.json,
        no_color=args.no_color,
    )

    report = run_scan(config)

    if args.json:
        print(format_json(report))
    else:
        print(format_terminal(report, no_color=args.no_color))

    return 0


if __name__ == "__main__":
    sys.exit(main())
