"""Acces au catalogue de regles (rules/rules.json).

Le catalogue est la source de verite : titre, gravite, categorie, remediation et
references. Le code ne fait que referencer des identifiants de regle via
`make_finding()`, ce qui garantit des messages coherents et testables.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from .models import Finding, normalize_severity

_CATALOGUE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "rules.json"
)

_CACHE: Dict[str, Dict[str, Any]] | None = None


def catalogue_path() -> str:
    """Chemin du fichier de catalogue de regles."""
    return _CATALOGUE_PATH


def load_rules(force: bool = False) -> Dict[str, Dict[str, Any]]:
    """Charge (et met en cache) le catalogue de regles."""
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE
    with open(_CATALOGUE_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    rules: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("rules", []):
        rule_id = str(entry.get("id", "")).upper()
        if not rule_id:
            continue
        entry["id"] = rule_id
        entry["severity"] = normalize_severity(entry.get("severity", "INFO"))
        rules[rule_id] = entry
    _CACHE = rules
    return rules


def rule(rule_id: str) -> Dict[str, Any]:
    """Retourne la definition d'une regle (ou un dict vide)."""
    return load_rules().get(str(rule_id).upper(), {})


def rule_ids() -> List[str]:
    """Liste triee des identifiants de regles connus."""
    return sorted(load_rules().keys())


def make_finding(
    rule_id: str,
    message: str,
    target: str = "",
    evidence: str = "",
    severity: str | None = None,
) -> Finding:
    """Construit un Finding a partir du catalogue.

    Args:
        rule_id: identifiant de regle (ex. "DS-DF-002").
        message: description concrete du probleme detecte.
        target: cible (chemin de Dockerfile, reference d'image, conteneur).
        evidence: extrait de preuve (ligne, fichier, valeur masquee).
        severity: force la gravite (sinon celle du catalogue).
    """
    definition = rule(rule_id)
    return Finding(
        rule_id=str(rule_id).upper(),
        title=definition.get("title", rule_id),
        severity=normalize_severity(severity or definition.get("severity", "INFO")),
        message=message,
        target=target,
        evidence=evidence,
        remediation=definition.get("remediation", ""),
        category=definition.get("category", ""),
        references=list(definition.get("references", [])),
    )
