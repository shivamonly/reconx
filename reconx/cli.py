import argparse
import re
import sys
import time

from reconx import __version__
from reconx.core.orchestrator import run_scan
from reconx.core.types import ScanConfig
from reconx.output.json_formatter import format_json
from reconx.output.terminal_formatter import format_terminal


BOLD = "\x1b[1m"
DIM = "\x1b[2m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
CYAN = "\x1b[36m"
RED = "\x1b[31m"
MAGENTA = "\x1b[35m"
RESET = "\x1b[0m"
CLS = "\x1b[2J\x1b[H"


def _c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def _banner() -> str:
    art = f"""
{_c('  .--------------------------------------------------------------.', CYAN)}
{_c('  |', CYAN)}{_c('  RRRRR   EEEEE   CCCC   OOOOO  NN  NN  XXXXX', YELLOW)}  {_c('|', CYAN)}
{_c('  |', CYAN)}{_c('  RR  R   EE     CC     OO  OO NNN NN  XX XX', YELLOW)}  {_c('|', CYAN)}
{_c('  |', CYAN)}{_c('  RRRR    EEEE   CC     OO  OO NN NNN   XXX ', YELLOW)}  {_c('|', CYAN)}
{_c('  |', CYAN)}{_c('  RR RR   EE     CC     OO  OO NN  NN  XX XX', YELLOW)}  {_c('|', CYAN)}
{_c('  |', CYAN)}{_c('  RR  RR  EEEEE   CCCC   OOOOO  NN  NN  XXXXX', YELLOW)}  {_c('|', CYAN)}
{_c('  |', CYAN)}                                                         {_c('|', CYAN)}
{_c('  |', CYAN)}  {_c('Web Reconnaissance & Security Analyzer', BOLD + GREEN)}              {_c('|', CYAN)}
{_c('  |', CYAN)}  {_c(f'v{__version__} - Passive Analysis Only', DIM)}                       {_c('|', CYAN)}
{_c('  `--------------------------------------------------------------\'', CYAN)}
"""
    return art


def _clear() -> None:
    if sys.stdout.isatty():
        print(CLS, end="")


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
        _clear()
        print(_banner())
        print(f"  {_c('.--------------------------------------------------------------.', CYAN)}")
        print(f"  {_c('|', CYAN)}              {_c('*  R E C O N X  *', BOLD + YELLOW)}                {_c('|', CYAN)}")
        print(f"  {_c('|--------------------------------------------------------------|', CYAN)}")
        print(f"  {_c('|', CYAN)}  {_c('[1]', GREEN)}  {_c('Scan a Target URL', BOLD)}{' ' * 41}{_c('|', CYAN)}")
        print(f"  {_c('|', CYAN)}  {_c('[2]', GREEN)}  {_c('Help / Documentation', BOLD)}     {' ' * 33}{_c('|', CYAN)}")
        print(f"  {_c('|', CYAN)}  {_c('[3]', GREEN)}  {_c('Developer Info', BOLD)}           {' ' * 35}{_c('|', CYAN)}")
        print(f"  {_c('|', CYAN)}  {_c('[4]', RED)}   {_c('Exit', BOLD)}                    {' ' * 41}{_c('|', CYAN)}")
        print(f"  {_c('`--------------------------------------------------------------\'', CYAN)}")
        print("")
        choice = input(f"  {_c('=>', GREEN)} Select option {_c('[1-4]', DIM)}: ").strip()

        if choice == "1":
            _clear()
            print(f"\n  {_c('--- Scan Target ---', BOLD + CYAN)}\n")
            target = input(f"  {_c('=>', GREEN)} Enter domain or URL: ").strip()
            if not target:
                print(f"\n  {_c('X', RED)} No target entered.")
                input(f"  {_c('Press Enter to continue...', DIM)}")
                continue
            print("")
            _run_scan_for_target(target)
            input(f"\n  {_c('Press Enter to return to menu...', DIM)}")
            continue

        elif choice == "2":
            _show_help()

        elif choice == "3":
            _show_dev_info()

        elif choice == "4":
            _clear()
            print(f"\n  {_c('* Thanks for using ReconX! *', GREEN)}")
            print(f"  {_c('Stay secure. Stay curious.', DIM)}\n")
            return 0

        else:
            print(f"\n  {_c('X Invalid option. Choose 1-4.', RED)}")
            time.sleep(1)


def _show_help() -> None:
    _clear()
    print(f"""
  {_c('.----------------------------------------------.', CYAN)}
  {_c('|', CYAN)}        {_c('*  HELP & DOCUMENTATION  *', BOLD + YELLOW)}        {_c('|', CYAN)}
  {_c('`----------------------------------------------\'', CYAN)}

    {_c('--- About', BOLD)}
  ReconX is a lightweight, terminal-based tool that assesses the
  externally observable security posture of a website using only
  passive analysis techniques.

    {_c('--- What It Does', BOLD)}
    {_c('v', GREEN)}  HTTP reachability, latency & redirect-chain analysis
    {_c('v', GREEN)}  Technology fingerprinting (framework, CMS, server)
    {_c('v', GREEN)}  Security header analysis (CSP, HSTS, XFO, cookies)
    {_c('v', GREEN)}  TLS/SSL certificate inspection
    {_c('v', GREEN)}  Composite security score with transparent weightings

  {_c('--- Quick Usage', BOLD)}
    {_c('$', GREEN)} reconx scan example.com          Full scan (all checks)
    {_c('$', GREEN)} reconx scan example.com --ssl    SSL/TLS only
    {_c('$', GREEN)} reconx scan example.com --tech   Tech detection only
    {_c('$', GREEN)} reconx scan example.com --json   Machine-readable output
    {_c('$', GREEN)} reconx --version                 Print version

  {_c('--- Flags', BOLD)}
    --headers                 Header analysis only
    --ssl                     SSL/TLS analysis only
    --tech                    Tech detection only
    --json                    JSON output
    --timeout <sec>           Request timeout (default: 5s)
    --no-color                Disable ANSI colors
    --verbose, -v             Show request/response metadata
    --allow-private-targets   Allow scanning private IPs

  {_c('--- Security Score', BOLD)}
    Score starts at 100 and deducts for missing controls:
    {_c('*', YELLOW)}  HTTPS not enforced           {_c('-30', RED)}
    {_c('*', YELLOW)}  Certificate expired          {_c('-40', RED)}
    {_c('*', YELLOW)}  HSTS missing                 {_c('-15', RED)}
    {_c('*', YELLOW)}  CSP missing                  {_c('-15', RED)}
    {_c('*', YELLOW)}  X-Frame-Options missing      {_c('-10', RED)}
    Buckets: {_c('Secure', GREEN)} (80-100) | {_c('Moderate', YELLOW)} (50-79) | {_c('Risky', RED)} (0-49)

  {_c('--- Responsible Use', BOLD)}
    Only scan targets you own or have permission to test.
    ReconX performs {_c('passive analysis only', BOLD)}.
""")
    input(f"  {_c('Press Enter to return to menu...', DIM)}")


def _show_dev_info() -> None:
    _clear()
    print(f"""
  {_c('.----------------------------------------------.', CYAN)}
  {_c('|', CYAN)}         {_c('*  DEVELOPER INFORMATION  *', BOLD + YELLOW)}        {_c('|', CYAN)}
  {_c('`----------------------------------------------\'', CYAN)}

    {_c('--- Developer', BOLD)}
    {_c('*', CYAN)}  Name:        Shivam Verma
    {_c('*', CYAN)}  Email:       workshivam@yahoo.com
    {_c('*', CYAN)}  GitHub:      https://github.com/Shivamonly
    {_c('*', CYAN)}  LinkedIn:    https://linkedin.com/in/shlvxm
    {_c('*', CYAN)}  Bio:         Cybersecurity enthusiast and BCA student
                   focused on building practical security tools and
                   web-based applications. Passionate about threat
                   analysis, secure development, and learning real-
                   world defensive techniques.
""")
    input(f"  {_c('Press Enter to return to menu...', DIM)}")


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
