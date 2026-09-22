"""Shared plumbing for the configuration scanners.

Every scanner (Dockerfile, Compose, daemon, container) needs the same three
things: a rule filter (``--ignore`` / ``--severity``), a way to build a
:class:`~src.models.Finding` from a rule id, and a way to accumulate findings
into a :class:`~src.models.ScanResult`. All of it lives here so that a new
scanner only has to contain the detection logic.
"""

from __future__ import annotations

from typing import Iterable, Optional

from .models import Category, Finding, Location, ScanResult, Severity
from .rules import RULES_BY_ID, unknown_rule_ids


class BaseScanner:
    """Common behaviour of the four configuration scanners.

    Subclasses set :attr:`category`, implement ``scan_text``/``scan_file`` and
    call :meth:`_emit` for every problem they detect. Filtering happens in
    :meth:`is_enabled`, which guarantees that ``--ignore`` and ``--severity``
    are honoured identically everywhere.
    """

    #: Rule category produced by this scanner (overridden by subclasses).
    category: Category = Category.DOCKERFILE

    def __init__(
        self,
        ignore: Iterable[str] = (),
        min_severity: Severity = Severity.INFO,
    ) -> None:
        self.ignore = {
            str(rule_id).strip().upper() for rule_id in ignore if str(rule_id).strip()
        }
        missing = unknown_rule_ids(sorted(self.ignore))
        if missing:
            raise ValueError("unknown rule id(s): " + ", ".join(missing))
        self.min_severity = min_severity

    # ------------------------------------------------------------------ filter
    def is_enabled(self, rule_id: str) -> bool:
        """Return ``True`` when ``rule_id`` passes the ignore/severity filter."""
        rule = RULES_BY_ID.get(rule_id)
        if rule is None:
            raise KeyError(f"unknown rule id {rule_id!r}")
        if rule.id in self.ignore:
            return False
        return rule.severity.rank >= self.min_severity.rank

    # ------------------------------------------------------------------ report
    def _new_result(self, target: str) -> ScanResult:
        """Create a result with the target and source already recorded."""
        result = ScanResult(target=target)
        result.add_source(target)
        return result

    def _emit(
        self,
        result: ScanResult,
        rule_id: str,
        *,
        location: Optional[Location] = None,
        message: str = "",
        evidence: str = "",
        remediation: str = "",
        reference: str = "",
    ) -> Optional[Finding]:
        """Add a finding for ``rule_id`` unless the rule is filtered out.

        The rule catalog provides the title, the severity, the default message
        and the default remediation, so a scanner only passes what it has
        actually observed (location, evidence, contextual message).
        """
        if not self.is_enabled(rule_id):
            return None
        rule = RULES_BY_ID[rule_id]
        finding = Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            category=rule.category,
            message=message or rule.description,
            location=location or Location(source=result.target),
            evidence=evidence,
            remediation=remediation or rule.remediation,
            reference=reference or rule.reference,
        )
        result.add(finding)
        return finding

    # ------------------------------------------------------------------- hooks
    def scan_file(self, path: str) -> ScanResult:  # pragma: no cover - interface
        """Scan a single file on disk."""
        raise NotImplementedError

    def scan_text(self, text: str, source: str) -> ScanResult:  # pragma: no cover
        """Scan in-memory content (used by the unit tests)."""
        raise NotImplementedError


def dedupe_findings(result: ScanResult) -> ScanResult:
    """Drop findings that share the same rule id and location.

    Two sources can legitimately produce the same finding (a Compose file that
    mounts the Docker socket, and the running container created from it). The
    orchestrator keeps the first occurrence and records it once.
    """
    seen = set()
    unique: list[Finding] = []
    for finding in result.findings:
        if finding.key in seen:
            continue
        seen.add(finding.key)
        unique.append(finding)
    result.findings = unique
    return result


__all__ = ["BaseScanner", "dedupe_findings"]