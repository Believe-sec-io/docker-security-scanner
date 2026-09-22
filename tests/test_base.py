"""Tests of the shared scanner plumbing (rule filtering and de-duplication)."""

from __future__ import annotations

from typing import Optional

import pytest

from src.base import BaseScanner, dedupe_findings
from src.models import Category, Finding, Location, ScanResult, Severity

class _DummyScanner(BaseScanner):
    """Minimal scanner used to exercise the base class in isolation."""

    category = Category.DOCKERFILE

    def emit(self, result: ScanResult, rule_id: str, **kwargs: object) -> Optional[Finding]:
        """Expose the protected emit of the base class to the tests."""
        return self._emit(result, rule_id, **kwargs)  # type: ignore[arg-type]


class TestRuleFiltering:
    def test_every_rule_is_enabled_by_default(self) -> None:
        scanner = _DummyScanner()
        assert scanner.is_enabled("DF-001") is True
        assert scanner.is_enabled("DM-001") is True

    def test_ignore_is_normalised_to_upper_case(self) -> None:
        scanner = _DummyScanner(ignore=["df-002"])
        assert scanner.is_enabled("DF-002") is False
        assert scanner.ignore == {"DF-002"}

    def test_min_severity_filters_lower_severities(self) -> None:
        scanner = _DummyScanner(min_severity=Severity.HIGH)
        assert scanner.is_enabled("DF-001") is True  # HIGH
        assert scanner.is_enabled("DF-010") is False  # MEDIUM
        assert scanner.is_enabled("DF-011") is False  # LOW

    def test_unknown_rule_ids_raise_on_construction(self) -> None:
        with pytest.raises(ValueError, match="unknown rule id"):
            _DummyScanner(ignore=["DF-404"])

    def test_emit_returns_none_for_a_filtered_rule(self) -> None:
        scanner = _DummyScanner(ignore=["DF-001"])
        result = ScanResult(target="Dockerfile")
        assert scanner.emit(result, "DF-001") is None
        assert result.findings == []

    def test_emit_fills_details_from_the_catalog(self) -> None:
        scanner = _DummyScanner()
        result = ScanResult(target="Dockerfile")
        finding = scanner.emit(result, "DF-001", evidence="no USER")
        assert finding is not None
        assert finding.title == "Container runs as root"
        assert finding.severity is Severity.HIGH
        assert finding.remediation
        assert finding.reference
        assert finding.location.source == "Dockerfile"
        assert finding.evidence == "no USER"

    def test_emit_accepts_overrides(self) -> None:
        scanner = _DummyScanner()
        result = ScanResult(target="Dockerfile")
        finding = scanner.emit(
            result,
            "DF-001",
            message="custom message",
            remediation="custom fix",
            location=Location(source="Dockerfile", line=12),
        )
        assert finding is not None
        assert finding.message == "custom message"
        assert finding.remediation == "custom fix"
        assert finding.location.line == 12

    def test_new_result_registers_the_source(self) -> None:
        result = _DummyScanner()._new_result("docker-compose.yml")
        assert result.target == "docker-compose.yml"
        assert result.sources == ["docker-compose.yml"]

    def test_is_enabled_rejects_an_unknown_rule(self) -> None:
        with pytest.raises(KeyError):
            _DummyScanner().is_enabled("ZZ-999")


class TestDeduplication:
    def _result(self) -> ScanResult:
        result = ScanResult(target=".")
        for _ in range(3):
            result.add(
                Finding(
                    rule_id="CP-001",
                    title="Privileged container",
                    severity=Severity.CRITICAL,
                    category=Category.COMPOSE,
                    message="m",
                    location=Location(source="docker-compose.yml", line=4, path="services.api"),
                )
            )
        result.add(
            Finding(
                rule_id="CP-001",
                title="Privileged container",
                severity=Severity.CRITICAL,
                category=Category.COMPOSE,
                message="m",
                location=Location(source="docker-compose.yml", line=9, path="services.worker"),
            )
        )
        return result

    def test_duplicates_are_collapsed(self) -> None:
        result = dedupe_findings(self._result())
        assert len(result.findings) == 2
        assert {finding.location.path for finding in result.findings} == {
            "services.api",
            "services.worker",
        }

    def test_the_first_occurrence_is_kept(self) -> None:
        result = dedupe_findings(self._result())
        assert result.findings[0].location.line == 4

    def test_a_unique_result_is_unchanged(self) -> None:
        result = ScanResult(target="Dockerfile")
        result.add(
            Finding(
                rule_id="DF-001",
                title="t",
                severity=Severity.HIGH,
                category=Category.DOCKERFILE,
                message="m",
            )
        )
        assert len(dedupe_findings(result).findings) == 1