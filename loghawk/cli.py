"""Command line interface for loghawk."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .engine import coverage, run
from .models import Report
from .parsers import parse_any
from .report import render
from .rules import Config
from .utils import utc_now

FORMATS = ("text", "md", "html", "json")
EXTENSIONS = {"text": "txt", "md": "md", "html": "html", "json": "json"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loghawk",
        description=(
            "Offline detection engine for authentication logs (OpenSSH auth.log and "
            "Windows Security CSV). Detects brute force, spray, enumeration, "
            "success-after-failure, privileged login, sudo escalation and off-hours access."
        ),
        epilog=(
            "examples:\n"
            "  loghawk samples/auth.log\n"
            "  loghawk samples/auth.log --threshold 3 --window 120 --format md\n"
            "  loghawk samples/windows-security.csv --format html --out reports\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("logfile", help="path to the log file (use '-' for stdin)")
    parser.add_argument("--window", type=int, default=300, help="detection window in seconds (default: 300)")
    parser.add_argument(
        "--lookback",
        type=int,
        default=3600,
        help="how far back to look for failures before a successful login (default: 3600)",
    )
    parser.add_argument("--threshold", type=int, default=5, help="failures per window to raise brute force (default: 5)")
    parser.add_argument("--enum-users", type=int, default=10, help="distinct usernames per window for enumeration (default: 10)")
    parser.add_argument("--spray-ips", type=int, default=5, help="distinct source IPs per account for spray (default: 5)")
    parser.add_argument("--work-start", type=int, default=8, help="first working hour, 24h clock (default: 8)")
    parser.add_argument("--work-end", type=int, default=18, help="last working hour, 24h clock (default: 18)")
    parser.add_argument("--year", type=int, help="year to assume for syslog lines without one (default: current year)")
    parser.add_argument("--format", choices=FORMATS, default="text", help="stdout format (default: text)")
    parser.add_argument("--out", metavar="DIR", help="also write report.{md,html,json} into DIR")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--quiet", action="store_true", help="write files only, no stdout")
    parser.add_argument("--version", action="version", version=f"loghawk {__version__}")
    return parser


def read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def run_cli(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    text = read_input(args.logfile)
    source = "stdin" if args.logfile == "-" else os.path.basename(args.logfile)

    events, errors, log_format = parse_any(text, year=args.year, source=source)
    config = Config(
        window=args.window,
        threshold=args.threshold,
        enum_distinct_users=args.enum_users,
        spray_distinct_ips=args.spray_ips,
        work_start=args.work_start,
        work_end=args.work_end,
        lookback=args.lookback,
    )
    findings = run(events, config)

    report = Report(
        source=source,
        generated_at=utc_now(),
        events=events,
        findings=findings,
        parse_errors=errors,
        window=args.window,
        threshold=args.threshold,
    )

    if not args.quiet:
        sys.stdout.write(render(report, args.format, colour=not args.no_color, log_format=log_format) + "\n")
        if log_format == "unknown" and not events:
            sys.stderr.write(
                "error: could not detect log format — expected OpenSSH auth.log or Windows Security CSV\n"
            )
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for fmt in ("md", "html", "json"):
            path = os.path.join(args.out, f"report.{EXTENSIONS[fmt]}")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(render(report, fmt, log_format=log_format))
            if not args.quiet:
                sys.stderr.write(f"wrote {path}\n")

    if not events:
        return 2
    return 1 if findings else 0


def main() -> None:
    raise SystemExit(run_cli())


def coverage_summary(events, findings) -> dict:
    return coverage(events, findings)
