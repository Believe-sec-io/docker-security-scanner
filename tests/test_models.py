"""Tests for the core data model (severities, findings, scan results)."""

from __future__ import annotations

import json

import pytest

from src.models import Category, Finding, Location, ScanResult, Severity


class TestSeverity:
    def test_rank_orders_critical_highest(self) -> None:
        assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank

    def test_from_name_is_case_insensitive(self) -> None:
        assert Severity.from_name("  HIGH ") is Severity.HIGH
        assert Severity.from_name("critical") is Severity.CRITICAL

    def test_from_name_rejects_unknown_value(self) -> None:
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.from_name("catastrophic")


class TestLocation:
    def test_display_combines_line_and_path(self) -> None:
        assert Location(source="a.yml", line=7).display() == "a.yml:7"
        assert Location(source="a.yml", path="services.api").display() == "a.yml: services.api"
        assert (
            Location(source="a.yml", line=7, path="services.api").display()
            == "a.yml:7 (services.api)"
        )

    def test_display_falls_back_on_unknown(self) -> None:
        assert Location().display() == "<unknown>"

    def test_round_trip_through_dict(self) -> None:
        location = Location(source="Dockerfile", line=3, path="USER")
        assert Location.from_dict(location.to_dict()) == location


class TestFinding:
    def _finding(self, **overrides: object) -> Finding:
        data = {
            "rule_id": "DF-001",
            "title": "Container runs as root",
            "severity": Severity.HIGH,
            "category": Category.DOCKERFILE,
            "message": "no USER instruction",
            "location": Location(source="Dockerfile", line=1),
        }
        data.update(overrides)
        return Finding(**data)  # type: ignore[arg-type]

    def test_key_identifies_the_location(self) -> None:
        finding = self._finding()
        assert finding.key == "DF-001@Dockerfile:1:"

    def test_to_dict_exposes_every_field(self) -> None:
        payload = self._finding(evidence="USER root").to_dict()
        assert payload["rule_id"] == "DF-001"
        assert payload["severity"] == "high"
        assert payload["category"] == "dockerfile"
        assert payload["evidence"] == "USER root"
        assert payload["location"]["source"] == "Dockerfile"

    def test_round_trip_through_dict(self) -> None:
        finding = self._finding(evidence="USER root")
        assert Finding.from_dict(finding.to_dict()) == finding


class TestScanResult:
    def _result(self) -> ScanResult:
        result = ScanResult(target=".")
        result.add_source("Dockerfile")
        result.add(Finding("DF-001", "t", Severity.HIGH, Category.DOCKERFILE, "m"))
        result.add(Finding("DF-014", "t", Severity.MEDIUM, Category.DOCKERFILE, "m"))
        result.add(Finding("DF-011", "t", Severity.LOW, Category.DOCKERFILE, "m"))
        return result

    def test_counts_include_zero_values(self) -> None:
        counts = self._result().counts
        assert counts["high"] == 1
        assert counts["critical"] == 0

    def test_worst_severity_of_an_empty_result_is_none(self) -> None:
        assert ScanResult().worst_severity() is None

    def test_sorted_findings_orders_by_severity(self) -> None:
        assert [f.rule_id for f in self._result().sorted_findings()] == [
            "DF-001",
            "DF-014",
            "DF-011",
        ]

    def test_failed_only_when_threshold_is_reached(self) -> None:
        result = self._result()
        assert result.failed(Severity.MEDIUM) is True
        assert result.failed(Severity.CRITICAL) is False
        assert result.failed(None) is False

    def test_add_source_is_idempotent(self) -> None:
        result = self._result()
        result.add_source("Dockerfile")
        assert result.sources == ["Dockerfile"]

    def test_to_dict_is_json_serialisable(self) -> None:
        payload = self._result().to_dict()
        assert payload["total_findings"] == 3
        assert payload["worst_severity"] == "high"
        assert isinstance(json.dumps(payload), str)

    def test_round_trip_through_dict(self) -> None:
        result = self._result()
        restored = ScanResult.from_dict(result.to_dict())
        assert restored.target == result.target
        assert restored.sources == result.sources
        assert [f.rule_id for f in restored.findings] == [f.rule_id for f in result.findings]
