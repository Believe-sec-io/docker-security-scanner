"""Modele de donnees du scanner : trouver une faille, agreger un rapport.

Tout est base sur la bibliotheque standard (dataclasses), aucune dependance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

# Ordre de gravite (plus grand = plus grave)
SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# Poids utilise pour le calcul du score de risque (0-100)
SEVERITY_WEIGHT: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH": 15,
    "MEDIUM": 6,
    "LOW": 2,
    "INFO": 0,
}

# Seuils (score max -> note)
GRADE_THRESHOLDS = ((0, "A"), (10, "B"), (25, "C"), (45, "D"), (100, "F"))

SEVERITIES: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def severity_value(severity: str) -> int:
    """Retourne la valeur numerique d'une gravite (0 si inconnue)."""
    return SEVERITY_ORDER.get(str(severity).upper(), 0)


def normalize_severity(severity: str) -> str:
    """Normalise une gravite en majuscules, INFO par defaut."""
    sev = str(severity).upper()
    return sev if sev in SEVERITY_ORDER else "INFO"


@dataclass
class Finding:
    """Une anomalie detectee sur une cible (image, Dockerfile, conteneur)."""

    rule_id: str
    title: str
    severity: str
    message: str
    target: str = ""
    evidence: str = ""
    remediation: str = ""
    category: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "target": self.target,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass
class Report:
    """Rapport complet d'un scan."""

    target: str
    target_type: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    # ------------------------------------------------------------------ ajout
    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    # -------------------------------------------------------------- analyse
    def counts(self) -> Dict[str, int]:
        """Comptage des constats par gravite (toutes gravites presentes)."""
        result = {sev: 0 for sev in SEVERITIES}
        for finding in self.findings:
            result[normalize_severity(finding.severity)] += 1
        return result

    def risk_score(self) -> int:
        """Score de risque 0-100 (borne) calcule sur les constats."""
        score = sum(SEVERITY_WEIGHT.get(normalize_severity(f.severity), 0) for f in self.findings)
        return min(100, score)

    def grade(self) -> str:
        """Note A-F derivee du score de risque."""
        score = self.risk_score()
        for threshold, grade in GRADE_THRESHOLDS:
            if score <= threshold:
                return grade
        return "F"

    def worst_severity(self) -> str:
        """Gravite la plus elevee detectee (INFO si aucun constat)."""
        if not self.findings:
            return "INFO"
        return max((normalize_severity(f.severity) for f in self.findings), key=severity_value)

    def filtered(self, min_severity: str = "INFO", ignore_rules: Iterable[str] = ()) -> "Report":
        """Retourne une copie du rapport filtree par gravite minimale / regles ignorees."""
        floor = severity_value(min_severity)
        ignored = {r.strip().upper() for r in ignore_rules if r.strip()}
        clone = Report(target=self.target, target_type=self.target_type, metadata=dict(self.metadata))
        clone.generated_at = self.generated_at
        clone.findings = [
            f
            for f in self.findings
            if severity_value(f.severity) >= floor and f.rule_id.upper() not in ignored
        ]
        clone.sort_findings()
        return clone

    def sort_findings(self) -> None:
        """Trie par gravite decroissante puis par identifiant de regle."""
        self.findings.sort(key=lambda f: (-severity_value(f.severity), f.rule_id, f.message))

    def has_findings_at_or_above(self, threshold: str) -> bool:
        """Vrai si au moins un constat atteint le seuil de gravite donne."""
        floor = severity_value(threshold)
        return any(severity_value(f.severity) >= floor for f in self.findings)

    # -------------------------------------------------------------- export
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "generated_at": self.generated_at,
            "risk_score": self.risk_score(),
            "grade": self.grade(),
            "worst_severity": self.worst_severity(),
            "summary": self.counts(),
            "total_findings": len(self.findings),
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
        }


def risk_label(score: int) -> str:
    """Libelle lisible associe au score de risque."""
    if score == 0:
        return "clean"
    if score <= 10:
        return "low risk"
    if score <= 25:
        return "moderate risk"
    if score <= 45:
        return "high risk"
    return "critical risk"
