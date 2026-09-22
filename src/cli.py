"""Command line interface of the Docker security scanner.

The CLI is deliberately thin: it validates the arguments, hands the work to
:class:`~src.scanner.Scanner`, renders the report with one of the renderers of
:mod:`src.reporters` and translates the outcome into an exit code that a CI job
can act on.

Exit codes
----------

``0``  nothing found at or above ``--fail-on``
``1``  at least one finding at or above ``--fail-on``
``2``  the command line could not be understood
``3``  the scan could not be completed (missing file, unreadable target, ...)
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, TextIO

from . import __version__
from .base import dedupe_findings
from .logger_config import configure_logging, get_logger
from .models import Category, ScanResult, Severity
from .reporters import render_console, render_json, render_markdown, render_sarif
from .rules import RULES, rules_by_category, unknown_rule_ids
from .scanner import CONCRETE_KINDS, TARGET_KINDS, Scanner

#: Process exit codes (documented in the README and in the ``--help`` output).
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

#: Report formats accepted by ``--format``.
FORMATS = ("console", "json", "markdown", "sarif")

#: ``--fail-on`` accepts the severities plus ``none`` (never fail).
FAIL_ON_CHOICES = ("none", *(severity.value for severity in Severity))

#: Renderers per format; ``console`` takes extra keyword arguments, so it is
#: wrapped to keep the dispatch table uniform.
def _render_console(result: ScanResult, options: "CliOptions") -> str:
    """Render the console report, honouring the CLI display options."""
    return render_console(
        result,
        color=options.color,
        show_evidence=not options.no_evidence,
        show_remediation=options.show_remediation,
    )


RENDERERS: Dict[str, Callable[[ScanResult, "CliOptions"], str]] = {
    "console": _render_console,
    "json": lambda result, _options: render_json(result),
    "markdown": lambda result, options: render_markdown(
        result, show_remediation=options.show_remediation
    ),
    "sarif": lambda result, _options: render_sarif(result, tool_version=__version__),
}

EPILOG = f"""\
examples:
  docker-security-scanner Dockerfile
  docker-security-scanner docker-compose.yml --format markdown --show-remediation
  docker-security-scanner . --severity medium --fail-on high
  docker-security-scanner daemon.json --kind daemon --format json --output report.json
  cat Dockerfile | docker-security-scanner --stdin --kind dockerfile
  docker inspect web | docker-security-scanner --stdin --kind container
  docker info --format '{{{{json .}}}}' > docker-info.json && docker-security-scanner docker-info.json
  docker-security-scanner --list-rules

exit codes:
  0  no finding at or above --fail-on
  1  at least one finding at or above --fail-on
  2  the command line could not be understood
  3  the scan could not be completed (missing file, unreadable target, ...)

target kinds:
  {CONCRETE_KINDS}
"""


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser of the command line interface."""
    parser = argparse.ArgumentParser(
        prog="docker-security-scanner",
        description=(
            "Audit the security configuration of a Docker setup: Dockerfiles, "
            "Compose files, daemon.json, docker info output and running "
            "containers (docker inspect). No daemon and no root access needed."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="file or directory to scan (default: the current directory)",
    )
    parser.add_argument(
        "-k",
        "--kind",
        choices=TARGET_KINDS,
        default="auto",
        help="force the configuration kind instead of detecting it (default: auto)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default="console",
        help="report format (default: console)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to PATH instead of stdout ('-' means stdout)",
    )
    parser.add_argument(
        "--severity",
        metavar="LEVEL",
        default="info",
        choices=[severity.value for severity in Severity],
        help="lowest severity to report (default: info, everything)",
    )
    parser.add_argument(
        "--fail-on",
        metavar="LEVEL",
        default="high",
        choices=FAIL_ON_CHOICES,
        help="exit with code 1 when a finding reaches LEVEL (default: high)",
    )
    parser.add_argument(
        "-i",
        "--ignore",
        metavar="RULE[,RULE]",
        action="append",
        default=[],
        help="rule id(s) to silence, repeatable (e.g. --ignore DF-014,CP-015)",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read the configuration from standard input instead of a file",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colours in the console report",
    )
    parser.add_argument(
        "--no-evidence",
        action="store_true",
        help="hide the observed values in the console report",
    )
    parser.add_argument(
        "--show-remediation",
        action="store_true",
        help="include the fix for every finding",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="print the rule catalog and exit (--format json is supported)",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="logging level written to stderr (default: WARNING)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="also append the logs to PATH",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


# ------------------------------------------------------------------ execution
@dataclass
class CliOptions:
    """Display options forwarded to the renderers."""

    color: bool = False
    show_remediation: bool = False
    no_evidence: bool = False


def main(
    argv: Optional[Sequence[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Run the command line interface and return the process exit code.

    ``stdout``/``stderr`` are injectable so that the tests can capture the report
    without redirecting the real streams.
    """
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    configure_logging(args.log_level, args.log_file)
    logger = get_logger("cli")

    if args.list_rules:
        if args.format not in ("console", "json", "markdown"):
            parser.error(f"--list-rules does not support --format {args.format}")
        _write(_render_rules(args.format), args.output, out, logger)
        return EXIT_OK

    ignore = _parse_ignore(parser, args.ignore)
    try:
        min_severity = Severity.from_name(args.severity)
        fail_on = None if args.fail_on == "none" else Severity.from_name(args.fail_on)
    except ValueError as exc:  # pragma: no cover - argparse already restricts the values
        parser.error(str(exc))
        return EXIT_USAGE  # unreachable, parser.error raises

    options = CliOptions(
        color=_use_color(args, out),
        show_remediation=args.show_remediation,
        no_evidence=args.no_evidence,
    )

    result, fatal = _collect(args, out, err, ignore, min_severity, logger)
    _write(RENDERERS[args.format](result, options), args.output, out, logger)

    if fatal:
        return EXIT_ERROR
    return EXIT_FINDINGS if result.failed(fail_on) else EXIT_OK


def entry_point() -> None:
    """Console-script entry point (``docker-security-scanner``)."""
    raise SystemExit(main())


def _parse_ignore(parser: argparse.ArgumentParser, values: Sequence[str]) -> List[str]:
    """Flatten ``--ignore`` values and reject an unknown rule id.

    A typo in ``--ignore`` must fail loudly: silently silencing nothing would
    give a false sense of safety to whoever reads the report.
    """
    rule_ids: List[str] = []
    for value in values:
        for item in str(value).split(","):
            cleaned = item.strip().upper()
            if cleaned:
                rule_ids.append(cleaned)
    missing = unknown_rule_ids(rule_ids)
    if missing:
        parser.error("unknown rule id(s) in --ignore: " + ", ".join(missing))
    return rule_ids


def _collect(
    args: argparse.Namespace,
    out: TextIO,
    err: TextIO,
    ignore: Sequence[str],
    min_severity: Severity,
    logger,
) -> tuple[ScanResult, bool]:
    """Run the scan over the requested targets and aggregate the outcome.

    Returns the merged :class:`~src.models.ScanResult` and whether the run was
    fatal (nothing at all could be scanned).
    """
    scanner = Scanner(ignore=ignore, min_severity=min_severity)

    if args.stdin:
        text = sys.stdin.read()
        if not text.strip():
            err.write("docker-security-scanner: nothing to scan on stdin\n")
            return ScanResult(target="<stdin>"), True
        result = scanner.scan_stdin_text(text, kind=args.kind, source_name="<stdin>")
        logger.debug("scanned %d bytes from stdin", len(text))
        return result, _is_fatal(result)

    targets = list(args.targets) or ["."]
    result = ScanResult(target=", ".join(targets) if len(targets) > 1 else targets[0])
    for target in targets:
        if not Path(target).exists():
            result.errors.append(f"{target}: no such file or directory")
            continue
        logger.debug("scanning %s", target)
        try:
            chunk = scanner.scan(target, kind=args.kind)
        except Exception as exc:  # a scanner bug must not abort a whole CI run
            logger.exception("unexpected failure while scanning %s", target)
            result.errors.append(f"{target}: unexpected failure: {exc}")
            continue
        _merge(result, chunk)
    dedupe_findings(result)
    return result, _is_fatal(result)


def _merge(accumulator: ScanResult, chunk: ScanResult) -> None:
    """Merge ``chunk`` into ``accumulator`` (findings, sources and errors)."""
    accumulator.extend(chunk.findings)
    for source in chunk.sources:
        accumulator.add_source(source)
    accumulator.errors.extend(chunk.errors)


def _is_fatal(result: ScanResult) -> bool:
    """True when the scan produced errors and could not read a single source."""
    return bool(result.errors) and not result.sources


def _use_color(args: argparse.Namespace, out: TextIO) -> bool:
    """Decide whether ANSI colours are appropriate for this run."""
    if args.no_color or args.format != "console":
        return False
    if args.output not in (None, "-"):
        return False
    return bool(getattr(out, "isatty", lambda: False)())


def _write(text: str, path: Optional[str], out: TextIO, logger) -> None:
    """Send ``text`` to stdout or to ``path`` (``-`` means stdout)."""
    if path and path != "-":
        destination = Path(path)
        if destination.parent and not destination.parent.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        logger.info("report written to %s", destination)
        return
    out.write(text)
    out.flush()


# --------------------------------------------------------------- rule catalog
def _render_rules(fmt: str = "console") -> str:
    """Render the rule catalog as a console table, JSON or Markdown.

    Exposing the catalog is what makes ``--ignore`` usable in practice: a
    reviewer reads the identifier and the description here instead of guessing
    it from the source code.
    """
    if fmt == "json":
        return json.dumps(
            [
                {
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity.value,
                    "category": rule.category.value,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "reference": rule.reference,
                }
                for rule in RULES
            ],
            indent=2,
            ensure_ascii=False,
        ) + "\n"
    if fmt == "markdown":
        return _rules_as_markdown()
    return _rules_as_table()


def _rules_as_table() -> str:
    """Render the catalog as an aligned plain-text table, grouped by category."""
    lines: List[str] = [
        f"docker-security-scanner rule catalog ({len(RULES)} rules)",
        "",
    ]
    for category in Category:
        rules = rules_by_category(category)
        lines.append(f"{category.value} ({len(rules)} rules)")
        lines.append("-" * 68)
        for rule in rules:
            lines.append(f"  {rule.id}  {rule.severity.value.upper():<8} {rule.title}")
            lines.append(f"        {_wrap(rule.description)}")
            lines.append(f"        fix: {_wrap(rule.remediation)}")
            lines.append("")
    return "\n".join(lines)


def _rules_as_markdown() -> str:
    """Render the catalog as a Markdown document (used to build ``docs/``)."""
    lines: List[str] = [
        "# Rule catalog",
        "",
        f"The scanner ships **{len(RULES)} rules**, split in four families: "
        "`DF-` (Dockerfile and image build), `CP-` (Docker Compose), "
        "`DM-` (Docker daemon) and `CT-` (running containers).",
        "",
        "Every rule has a stable identifier that can be passed to `--ignore`.",
        "",
    ]
    for category in Category:
        rules = rules_by_category(category)
        lines.append(f"## {category.value.capitalize()} (`{rules[0].id[:2]}-`)")
        lines.append("")
        lines.append("| Rule | Severity | Title | Why it matters | Fix |")
        lines.append("| --- | --- | --- | --- | --- |")
        for rule in rules:
            lines.append(
                f"| `{rule.id}` | {rule.severity.value} | {rule.title} "
                f"| {_cell(rule.description)} | {_cell(rule.remediation)} |"
            )
        lines.append("")
        lines.append(f"*Reference: {rules[0].reference}*")
        lines.append("")
    return "\n".join(lines)


def _wrap(text: str, width: int = 76, indent: str = "") -> str:
    """Wrap ``text`` on ``width`` columns for the console catalog view."""
    return textwrap.fill(
        " ".join(str(text or "").split()),
        width=width,
        subsequent_indent=indent,
    )


def _cell(text: str) -> str:
    """Make ``text`` safe inside a Markdown table cell."""
    return " ".join(str(text or "").split()).replace("|", "\\|")


__all__ = [
    "EXIT_ERROR",
    "EXIT_FINDINGS",
    "EXIT_OK",
    "EXIT_USAGE",
    "FORMATS",
    "build_parser",
    "entry_point",
    "main",
]


if __name__ == "__main__":  # allows ``python -m src.cli``
    raise SystemExit(main())