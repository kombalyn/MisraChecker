"""
misra-checker CLI

Usage:
    misra-checker path/to/file.c
    misra-checker src/ --standard MISRA_C_2012 --severity mandatory required
    misra-checker main.py --output sarif --out results.sarif
    misra-checker main.py --disable-rules PY2024-5.4 PY2024-5.5
    misra-checker main.py --enable-rules PY2024-1.1 PY2024-6.1
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .checker import MISRAChecker
from .models import CheckReport, Severity, Standard


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="misra-checker",
        description="MISRA C:2012 / MISRA C++:2023 / MISRA Python:2024 compliance checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  misra-checker main.c
  misra-checker src/ --recursive
  misra-checker main.py --output json
  misra-checker app.cpp --standard MISRA_CPP_2023 --severity mandatory required
  misra-checker main.py --disable-rules PY2024-5.4 PY2024-8.3
        """,
    )
    p.add_argument(
        "paths", nargs="+",
        help="Source file(s) or director(y/ies) to check",
    )
    p.add_argument(
        "--standard", "-s",
        choices=[s.value for s in Standard],
        default=None,
        help="Force a specific standard (default: auto-detect from file extension)",
    )
    p.add_argument(
        "--severity", nargs="+",
        choices=["mandatory", "required", "advisory", "info"],
        default=None,
        help="Only report violations at these severity levels",
    )
    p.add_argument(
        "--output", "-o",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--out", metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    p.add_argument(
        "--recursive", "-r", action="store_true",
        help="Recurse into directories",
    )
    p.add_argument(
        "--disable-rules", nargs="+", metavar="RULE_ID", default=[],
        help="Rule IDs to disable (e.g. PY2024-5.4 C2012-15.5)",
    )
    p.add_argument(
        "--enable-rules", nargs="+", metavar="RULE_ID", default=[],
        help="Only check these specific rule IDs",
    )
    p.add_argument(
        "--no-suppress", action="store_true",
        help="Ignore inline MISRA-suppress comments",
    )
    p.add_argument(
        "--list-rules", action="store_true",
        help="List all known rules and exit",
    )
    p.add_argument(
        "--extensions", nargs="+", metavar="EXT", default=None,
        help="File extensions to check when scanning directories (e.g. .c .h)",
    )
    p.add_argument(
        "--fail-on", choices=["any", "mandatory", "required", "never"],
        default="required",
        help="Exit code: 'any' = any violation, 'required' = mandatory+required, 'never' = always 0",
    )
    return p


def list_rules(standard: Optional[str]) -> None:
    from .rules.registry import get_registry, get_rules_for_standard
    registry = get_registry()
    rules = (
        get_rules_for_standard(Standard(standard))
        if standard else list(registry.values())
    )
    rules = sorted(rules, key=lambda r: r.rule_id)
    print(f"{'Rule ID':<25} {'Standard':<18} {'Severity':<12} {'Category':<25} Title")
    print("-" * 100)
    for r in rules:
        print(
            f"{r.rule_id:<25} {r.standard.value:<18} {r.severity.value:<12} "
            f"{r.category.value:<25} {r.title}"
        )
    print(f"\nTotal: {len(rules)} rules")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    if args.list_rules:
        list_rules(args.standard)
        return 0

    std = Standard(args.standard) if args.standard else None
    checker = MISRAChecker(
        standard=std,
        severity_filter=args.severity,
        enabled_rules=args.enable_rules or None,
        disabled_rules=args.disable_rules,
        suppress_comments=not args.no_suppress,
    )

    # Aggregate report across all paths
    reports: List[CheckReport] = []
    for raw_path in args.paths:
        p = Path(raw_path)
        if not p.exists():
            print(f"ERROR: Path does not exist: {p}", file=sys.stderr)
            continue
        if p.is_dir():
            reports.append(checker.check_directory(
                p,
                recursive=args.recursive,
                extensions=args.extensions,
            ))
        else:
            reports.append(checker.check_file(p))

    if not reports:
        print("No files checked.", file=sys.stderr)
        return 1

    # Merge reports
    merged = _merge_reports(reports, std or Standard.C2012)

    # Render
    output = _render(merged, args.output)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Report written to: {args.out}")
    else:
        print(output)

    # Exit code
    return _exit_code(merged, args.fail_on)


def _merge_reports(reports: List[CheckReport], std: Standard) -> CheckReport:
    from .models import CheckReport
    merged = CheckReport(standard=std)
    for r in reports:
        merged.files.extend(r.files)
        merged.violations.extend(r.violations)
        merged.errors.extend(r.errors)
    return merged


def _render(report: CheckReport, fmt: str) -> str:
    if fmt == "json":
        return report.to_json()
    if fmt == "sarif":
        return json.dumps(report.to_sarif(), indent=2)
    return report.summary()


def _exit_code(report: CheckReport, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if fail_on == "any" and report.active_violations:
        return 1
    if fail_on in ("required", "mandatory"):
        if report.mandatory_count > 0 or report.required_count > 0:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
