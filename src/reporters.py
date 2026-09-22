"""Report renderers: console, JSON, Markdown and SARIF.

A scan result is worth nothing if it cannot be consumed: the console output is
for the developer who runs the tool by hand, the JSON for a script, the
Markdown for the pull-request comment and the SARIF for the code-scanning tab
of the forge. All four live here and share the same ordering
(:meth:`src.models.ScanResult.sorted_findings`), so the same finding always
appears in the same position.

The renderers are pure functions of a :class:`~src.models.ScanResult`: they
never read a file, never change the model and never raise on an empty result.
"""

from __future__ import annotations

import json
from typing import Callable, Dict, Iterable, List, Optional, Sequence, TextIO

from .models import SEVERITY_TAG, Category, Finding, ScanResult, Severity
from .rules import RULES

#: ANSI colour per severity (disabled with ``--no-color`` or when not a TTY).
SEVERITY_COLOR: Dict[Severity, str] = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[0;37m",
}

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

#: Order used by the summary line.
SEVERITY_ORDER: Sequence[Severity] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)



def render_json(result: ScanResult, indent: int = 2) -> str:
    """Render ``result`` as a JSON document (machine readable, stable keys)."""
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False) + "\n"


def render_console(
    result: ScanResult,
    color: bool = False,
    show_evidence: bool = True,
    show_remediation: bool = False,
) -> str:
    """Render ``result`` as a human readable report.

    ``color`` adds ANSI escapes, ``show_evidence`` controls the observed-value
    line and ``show_remediation`` adds the fix to every finding (useful when the
    report is pasted into a ticket).
    """
    lines: List[str] = []
    target = result.target or "<no target>"
    lines.append(f"{_paint('Docker security scan: ' + target, BOLD, color)}")
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append(_paint("No insecure configuration found.", "\033[1;32m", color))
    for finding in findings:
        tag = SEVERITY_TAG[finding.severity]
        header = f"[{tag:<4}] {finding.rule_id}  {finding.title}"
        lines.append(_paint(header, SEVERITY_COLOR[finding.severity], color))
        lines.append(f"        at {finding.location.display()}")
        if finding.message:
            lines.append(f"        {finding.message}")
        if show_evidence and finding.evidence:
            lines.append(_paint(f"        evidence: {finding.evidence}", DIM, color))
        if show_remediation and finding.remediation:
            lines.append(f"        fix: {finding.remediation}")
        lines.append("")

    for error in result.errors:
        lines.append(_paint(f"[ERR ] {error}", "\033[1;31m", color))

    lines.extend(_summary_lines(result, color))
    return "\n".join(lines) + "\n"


def _summary_lines(result: ScanResult, color: bool) -> List[str]:
    """Return the trailing summary block of the console report."""
    counts = result.counts
    parts = [f"{severity.value}: {counts[severity.value]}" for severity in SEVERITY_ORDER]
    lines = [
        "-" * 68,
        f"Findings: {result.total}  ({', '.join(parts)})",
        f"Sources scanned: {len(result.sources)}",
    ]
    worst = result.worst_severity()
    lines.append(f"Worst severity: {worst.value if worst else 'none'}")
    if result.errors:
        lines.append(f"Errors: {len(result.errors)}")
    return [_paint(line, DIM, color) for line in lines]


def _paint(text: str, code: str, enabled: bool) -> str:
    """Wrap ``text`` in an ANSI sequence when colour is enabled."""
    if not enabled or not code:
        return text
    return f"{code}{text}{RESET}"


def render_markdown(result: ScanResult, show_remediation: bool = True) -> str:
    """Render ``result`` as Markdown, ready for a pull-request comment.

    Every finding becomes a row of a single table so that a reviewer can scan
    the report quickly; a collapsed ``<details>`` block repeats the evidence,
    which keeps the comment readable even when a Compose file has 40 findings.
    """
    target = result.target or "<no target>"
    lines: List[str] = [f"## Docker security scan: `{target}`", ""]

    counts = result.counts
    summary = " | ".join(f"{severity.value}: **{counts[severity.value]}**" for severity in SEVERITY_ORDER)
    lines.append(f"**Findings:** {result.total} ({summary})")
    worst = result.worst_severity()
    lines.append(f"**Worst severity:** {worst.value if worst else 'none'}")
    lines.append("")
    lines.append(f"**Sources scanned:** {len(result.sources)}")
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append("No insecure configuration found. :white_check_mark:")
        return "\n".join(lines) + "\n"

    lines.append("| Severity | Rule | Location | Finding |")
    lines.append("| --- | --- | --- | --- |")
    for finding in findings:
        location = finding.location.display().replace("|", "\\|")
        message = finding.message.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {SEVERITY_TAG[finding.severity]} | `{finding.rule_id}` | `{location}` | "
            f"{finding.title} — {message} |"
        )
    lines.append("")

    details = [finding for finding in findings if finding.evidence or finding.remediation]
    if details:
        lines.append("<details><summary>Details and remediation</summary>")
        lines.append("")
        for finding in details:
            lines.append(f"### `{finding.rule_id}` {finding.title}")
            lines.append("")
            lines.append(f"- Location: `{finding.location.display()}`")
            if finding.evidence:
                lines.append(f"- Evidence: `{finding.evidence}`")
            if finding.remediation and show_remediation:
                lines.append(f"- Remediation: {finding.remediation}")
            if finding.reference:
                lines.append(f"- Reference: {finding.reference}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    if result.errors:
        lines.append("### Errors")
        lines.append("")
        for error in result.errors:
            lines.append(f"- `{error}`")
        lines.append("")

    return "\n".join(lines)


def render_sarif(result: ScanResult, tool_version: str = "1.0.0") -> str:
    """Render ``result`` as SARIF 2.1.0 for the code-scanning tab of a forge.

    The rule metadata comes from the catalog, so a report always explains every
    rule it references (a SARIF consumer refuses a result whose rule is not
    declared in ``tool.driver.rules``).
    """
    used_rules = {finding.rule_id for finding in result.findings}
    rules = [
        {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": f"{rule.description}\n\nRemediation: {rule.remediation}"},
            "helpUri": rule.reference or "https://docs.docker.com/engine/security/",
            "defaultConfiguration": {"level": _sarif_level(rule.severity)},
            "properties": {"tags": [rule.category.value], "severity": rule.severity.value},
        }
        for rule in RULES
        if rule.id in used_rules
    ]

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "docker-security-scanner",
                        "informationUri": "https://github.com/Believe-sec-io/docker-security-scanner",
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "results": [_sarif_result(finding) for finding in result.sorted_findings()],
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": error}}
                            for error in result.errors
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _sarif_result(finding: Finding) -> Dict[str, object]:
    """Build one SARIF ``result`` object from a finding."""
    physical: Dict[str, object] = {
        "artifactLocation": {"uri": finding.location.source or "unknown"},
    }
    if finding.location.line:
        physical["region"] = {"startLine": max(1, finding.location.line)}
    properties: Dict[str, object] = {
        "severity": finding.severity.value,
        "category": finding.category.value,
        "path": finding.location.path,
        "remediation": finding.remediation,
    }
    if finding.evidence:
        properties["evidence"] = finding.evidence
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message or finding.title},
        "locations": [{"physicalLocation": physical}],
        "properties": properties,
    }


def _sarif_level(severity: Severity) -> str:
    """Map a scanner severity onto a SARIF level (``error``/``warning``/``note``)."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity in (Severity.MEDIUM, Severity.LOW):
        return "warning"
    return "note"