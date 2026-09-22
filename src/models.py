"""Core data model: severities, locations, findings and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence


class Severity(str, Enum):
    """Severity levels, ordered from the most to the least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric weight, used for sorting (``CRITICAL`` is the highest)."""
        return _SEVERITY_RANK[self]

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """Parse a severity from a user supplied value (case-insensitive)."""
        try:
            return cls(str(name).strip().lower())
        except ValueError:
            valid = ", ".join(severity.value for severity in cls)
            raise ValueError(f"unknown severity {name!r} (expected one of: {valid})") from None


_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

#: Short tags used by the console reporter.
SEVERITY_TAG: Dict[Severity, str] = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


class Category(str, Enum):
    """Which kind of configuration a rule applies to."""

    DOCKERFILE = "dockerfile"
    COMPOSE = "compose"
    DAEMON = "daemon"
    CONTAINER = "container"


@dataclass(frozen=True)
class Location:
    """Where a finding was detected.

    ``source`` is a file path or a logical name (container name, ``daemon.json``),
    ``line`` is a 1-based line number when the source is a line oriented file and
    ``path`` is the configuration path inside structured documents
    (e.g. ``services.api.privileged``).
    """

    source: str = ""
    line: int = 0
    path: str = ""

    def display(self) -> str:
        """Compact one-line rendering used by the console reporter."""
        if self.line and self.path:
            return f"{self.source}:{self.line} ({self.path})"
        if self.line:
            return f"{self.source}:{self.line}"
        if self.path:
            return f"{self.source}: {self.path}"
        return self.source or "<unknown>"

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "line": self.line, "path": self.path}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Location":
        return cls(
            source=str(data.get("source", "")),
            line=int(data.get("line", 0) or 0),
            path=str(data.get("path", "")),
        )


@dataclass(frozen=True)
class Finding:
    """A single insecure configuration detected by the scanner."""

    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    location: Location = field(default_factory=Location)
    evidence: str = ""
    remediation: str = ""
    reference: str = ""

    @property
    def key(self) -> str:
        """Identity used for de-duplication."""
        return f"{self.rule_id}@{self.location.source}:{self.location.line}:{self.location.path}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
            "location": self.location.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            rule_id=str(data["rule_id"]),
            title=str(data.get("title", "")),
            severity=Severity.from_name(data["severity"]),
            category=Category(str(data["category"])),
            message=str(data.get("message", "")),
            location=Location.from_dict(data.get("location", {}) or {}),
            evidence=str(data.get("evidence", "")),
            remediation=str(data.get("remediation", "")),
            reference=str(data.get("reference", "")),
        )


@dataclass
class ScanResult:
    """Aggregated outcome of a scan over one or more sources."""

    target: str = ""
    findings: List[Finding] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: Sequence[Finding]) -> None:
        self.findings.extend(findings)

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)

    def count(self, severity: Severity) -> int:
        return sum(1 for finding in self.findings if finding.severity is severity)

    @property
    def counts(self) -> Dict[str, int]:
        """Finding count per severity, zeros included (JSON friendly keys)."""
        return {severity.value: self.count(severity) for severity in Severity}

    @property
    def total(self) -> int:
        return len(self.findings)

    def worst_severity(self) -> Optional[Severity]:
        """Highest severity found, or ``None`` when the scan is clean."""
        if not self.findings:
            return None
        return max((finding.severity for finding in self.findings), key=lambda s: s.rank)

    def sorted_findings(self) -> List[Finding]:
        """Findings ordered by severity, then by source, line and rule id."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.location.source, f.location.line, f.rule_id),
        )

    def has_at_or_above(self, severity: Severity) -> bool:
        """True when at least one finding is as severe as ``severity``."""
        return any(finding.severity.rank >= severity.rank for finding in self.findings)

    def failed(self, fail_on: Optional[Severity]) -> bool:
        """Whether the scan should make a CI job fail (``None`` never fails)."""
        if fail_on is None:
            return False
        return self.has_at_or_above(fail_on)

    def to_dict(self) -> Dict[str, Any]:
        worst = self.worst_severity()
        return {
            "target": self.target,
            "sources": list(self.sources),
            "errors": list(self.errors),
            "counts": self.counts,
            "total_findings": self.total,
            "worst_severity": worst.value if worst else None,
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        result = cls(target=str(data.get("target", "")))
        result.sources = list(data.get("sources", []))
        result.errors = list(data.get("errors", []))
        result.findings = [Finding.from_dict(item) for item in data.get("findings", [])]
        return result