"""
Seraph CLI — supply chain security scanner.
"""

import argparse
import sys

from seraph import __version__
from seraph.base import Scanner, ScanResult
from seraph.scanners import IntegrityScanner, PersistenceScanner, PthScanner, PycScanner, SourceScanner


# All active scanners — add new ones here
SCANNERS: list[Scanner] = [
    PthScanner(),
    PycScanner(),
    SourceScanner(),
    PersistenceScanner(),
    IntegrityScanner(),
]


def _print_result(result: ScanResult) -> None:
    print(f"[{result.scanner}] Scanned {len(result.scanned)} file(s)", end="  ")
    if result.is_clean:
        print("OK")
    else:
        print(f"ALERT — {len(result.findings)} finding(s)")
        for f in result.findings:
            location = f"{f.file}:{f.line_number}" if f.line_number else str(f.file)
            print(f"  {location}")
            if f.line:
                print(f"  {f.line}")
            print(f"  pattern: '{f.matched_pattern}'")
            print()


def cmd_scan(ci: bool) -> int:
    found = False
    for scanner in SCANNERS:
        result = scanner.run()
        _print_result(result)
        found |= not result.is_clean
    return 1 if (ci and found) else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="seraph",
        description="Supply chain security scanner",
    )
    parser.add_argument("--version", action="version", version=f"seraph {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run all scanners")
    scan_parser.add_argument(
        "--ci",
        action="store_true",
        help="Exit with code 1 if findings are detected (for CI pipelines)",
    )

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(ci=args.ci))
    else:
        parser.print_help()
        sys.exit(0)
