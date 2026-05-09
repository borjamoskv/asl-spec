"""CLI entry point: python -m asl_check [path] or asl-check [path]."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checker import CheckResult, check
from .parser import ParseError, parse_file


def _find_asl_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(target.rglob("*.asl"))
    return []


def _print_result(path: Path, result: CheckResult) -> None:
    status = "\033[32mPASS\033[0m" if result.passed else "\033[31mFAIL\033[0m"
    print(f"\n{'─' * 60}")
    print(f"  {status}  {path}")
    print(f"  agents: {result.agent_count}  statements: {result.statement_count}"
          f"  threat coverage: {result.coverage_pct}%")

    for d in result.diagnostics:
        color = {"error": "\033[31m", "warning": "\033[33m", "info": "\033[90m"}.get(d.level, "")
        print(f"{color}{d}\033[0m")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="asl-check",
        description="ASL compiler — parse and verify .asl agent specifications",
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="file or directory to check (default: current dir)")
    parser.add_argument("-v", "--version", action="version", version=f"asl-check {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print PASS/FAIL")
    args = parser.parse_args(argv)

    target = Path(args.path).resolve()
    files = _find_asl_files(target)

    if not files:
        print(f"\033[31m✗ no .asl files found in {target}\033[0m", file=sys.stderr)
        return 1

    print(f"\033[1masl-check {__version__}\033[0m — scanning {len(files)} file(s)")

    all_passed = True
    for f in files:
        try:
            spec = parse_file(f)
            result = check(spec)
        except ParseError as e:
            result = CheckResult()
            result.error(f"parse error: {e}")

        if not result.passed:
            all_passed = False

        if not args.quiet:
            _print_result(f, result)
        else:
            tag = "PASS" if result.passed else "FAIL"
            print(f"  {tag}  {f}")

    print(f"\n{'─' * 60}")
    if all_passed:
        print(f"\033[32m✓ all {len(files)} specification(s) valid\033[0m")
        return 0
    else:
        print(f"\033[31m✗ verification failed\033[0m")
        return 1


if __name__ == "__main__":
    sys.exit(main())
