"""Integration tests over the sample files shipped in ``examples/``.

These tests are the contract of the repository: the hardened samples must stay
clean (they document how to configure Docker correctly) and the insecure ones
must keep triggering the rules they illustrate (they are the regression suite
for the rule engine, and the demo material of the README).
"""

from __future__ import annotations

from typing import Set

import pytest

from src.models import Severity
from src.scanner import Scanner
from src.rules import RULES_BY_ID
from tests.helpers import rule_ids

#: Rules each insecure sample must report. The list is explicit on purpose: a
#: rule that silently stops working is a regression, and this is what catches it.
EXPECTED_RULES = {
    "Dockerfile.insecure": {
        "DF-002",
        "DF-003",
        "DF-004",
        "DF-005",
        "DF-006",
        "DF-007",
        "DF-008",
        "DF-009",
        "DF-010",
        "DF-011",
        "DF-012",
        "DF-013",
        "DF-014",
        "DF-015",
    },
    "docker-compose.insecure.yml": {f"CP-{index:03d}" for index in range(1, 17)},
    "daemon.json.insecure": {f"DM-{index:03d}" for index in range(1, 14)},
    "docker-inspect.insecure.json": {f"CT-{index:03d}" for index in range(1, 18)},
}

#: Samples that must produce no finding at all.
CLEAN_EXAMPLES = (
    "Dockerfile.secure",
    "docker-compose.secure.yml",
    "daemon.json.secure",
    "docker-inspect.secure.json",
)


def _scan(examples_dir, name: str):
    """Scan one sample file of ``examples/``."""
    return Scanner().scan(str(examples_dir / name))


@pytest.mark.parametrize("name", sorted(CLEAN_EXAMPLES))
def test_hardened_examples_are_clean(examples_dir, name: str) -> None:
    result = _scan(examples_dir, name)
    assert result.errors == [], result.errors
    assert result.findings == [], [finding.rule_id for finding in result.findings]


@pytest.mark.parametrize("name", sorted(EXPECTED_RULES))
def test_insecure_examples_report_the_expected_rules(examples_dir, name: str) -> None:
    result = _scan(examples_dir, name)
    assert result.errors == [], result.errors
    missing = EXPECTED_RULES[name] - set(rule_ids(result))
    assert not missing, f"{name} no longer reports: {sorted(missing)}"


def test_the_insecure_dockerfile_is_severe_enough_to_fail_a_build(examples_dir) -> None:
    result = _scan(examples_dir, "Dockerfile.insecure")
    assert result.has_at_or_above(Severity.CRITICAL)
    assert result.failed(Severity.HIGH) is True


def test_the_docker_info_sample_is_scanned_in_host_mode(examples_dir) -> None:
    result = _scan(examples_dir, "docker-info.insecure.json")
    assert result.errors == []
    assert {"DM-002", "DM-006", "DM-008"} <= set(rule_ids(result))


def test_every_example_finding_maps_to_a_catalog_rule(examples_dir) -> None:
    """No finding may reference a rule that is absent from the catalog."""
    for name in sorted(EXPECTED_RULES):
        for finding in _scan(examples_dir, name).findings:
            assert finding.rule_id in RULES_BY_ID
            assert finding.title == RULES_BY_ID[finding.rule_id].title
            assert finding.remediation


def test_a_directory_scan_of_the_examples_is_reproducible(examples_dir) -> None:
    """Scanning the whole folder twice gives the same rules, in the same order."""
    first = Scanner().scan(str(examples_dir))
    second = Scanner().scan(str(examples_dir))
    assert [f.rule_id for f in first.sorted_findings()] == [
        f.rule_id for f in second.sorted_findings()
    ]
    assert len(first.sources) >= len(EXPECTED_RULES)


def test_the_hardened_examples_are_the_only_clean_ones(examples_dir) -> None:
    insecure: Set[str] = set(EXPECTED_RULES)
    for name in sorted(insecure):
        assert _scan(examples_dir, name).findings, f"{name} should report findings"