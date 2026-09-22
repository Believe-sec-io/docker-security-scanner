"""Tests of the report renderers (console, JSON, Markdown, SARIF)."""

from __future__ import annotations

import json

import pytest

from src.models import Category, Finding, Location, ScanResult, Severity
from src.reporters import render_console, render_json, render_markdown, render_sarif


def _result() -> ScanResult:
    result = ScanResult(target="examples")
    result.add_source("Dockerfile")
    result.add(
        Finding(
            rule_id="DF-002",
            title="Root user set explicitly",
            severity=Severity.HIGH,
            category=Category.DOCKERFILE,
            message="The image sets USER root.",
            location=Location(source="Dockerfile", line=7),
            evidence="USER root",
            remediation="Switch to an unprivileged account.",
        )
    )
    result.add(
        Finding(
            rule_id="CP-001",
            title="Privileged container",
            severity=Severity.CRITICAL,
            category=Category.COMPOSE,
            message="privileged: true was found.",
            location=Location(source="docker-compose.yml", line=4, path="services.api"),
            remediation="Remove privileged: true.",
        )
    )
    return result


def _empty() -> ScanResult:
    result = ScanResult(target="Dockerfile")
    result.add_source("Dockerfile")
    return result


class TestConsoleRenderer:
    def test_lists_findings_with_severity_tags(self) -> None:
        text = render_console(_result())
        assert "[CRIT] CP-001" in text
        assert "[HIGH] DF-002" in text
        assert "Dockerfile:7" in text

    def test_shows_the_summary_line(self) -> None:
        text = render_console(_result())
        assert "Findings: 2" in text
        assert "Worst severity: critical" in text
        assert "Sources scanned: 1" in text

    def test_clean_scan_says_so(self) -> None:
        assert "No insecure configuration found." in render_console(_empty())

    def test_evidence_and_remediation_are_optional(self) -> None:
        without = render_console(_result(), show_evidence=False, show_remediation=False)
        assert "evidence:" not in without
        assert "fix:" not in without
        with_details = render_console(_result(), show_evidence=True, show_remediation=True)
        assert "evidence: USER root" in with_details
        assert "fix: Remove privileged: true." in with_details

    def test_color_adds_ansi_escapes_only_when_requested(self) -> None:
        assert "\033[" not in render_console(_result())
        assert "\033[" in render_console(_result(), color=True)

    def test_errors_are_rendered(self) -> None:
        result = _empty()
        result.errors.append("something failed")
        text = render_console(result)
        assert "[ERR ] something failed" in text
        assert "Errors: 1" in text


class TestJsonRenderer:
    def test_is_valid_json_with_stable_keys(self) -> None:
        payload = json.loads(render_json(_result()))
        assert payload["target"] == "examples"
        assert payload["total_findings"] == 2
        assert payload["counts"]["critical"] == 1
        assert payload["worst_severity"] == "critical"

    def test_findings_are_sorted_by_severity(self) -> None:
        payload = json.loads(render_json(_result()))
        assert [item["rule_id"] for item in payload["findings"]] == ["CP-001", "DF-002"]

    def test_clean_scan_produces_an_empty_list(self) -> None:
        payload = json.loads(render_json(_empty()))
        assert payload["findings"] == []
        assert payload["worst_severity"] is None


class TestMarkdownRenderer:
    def test_builds_a_table_ordered_by_severity(self) -> None:
        text = render_markdown(_result())
        assert "## Docker security scan: `examples`" in text
        assert "| Severity | Rule | Location | Finding |" in text
        assert text.index("CP-001") < text.index("DF-002")

    def test_clean_scan_is_announced(self) -> None:
        assert "No insecure configuration found." in render_markdown(_empty())

    def test_findings_with_details_are_collapsed(self) -> None:
        text = render_markdown(_result(), show_remediation=True)
        assert "<details>" in text
        assert "Switch to an unprivileged account." in text

    def test_pipes_in_messages_are_escaped(self) -> None:
        result = _result()
        finding = result.findings[0]
        result.findings[0] = Finding(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            category=finding.category,
            message="a | b",
            location=finding.location,
        )
        assert r"a \| b" in render_markdown(result)


class TestSarifRenderer:
    def test_header_matches_the_sarif_version(self) -> None:
        document = json.loads(render_sarif(_result(), tool_version="9.9.9"))
        assert document["version"] == "2.1.0"
        assert document["$schema"].endswith("sarif-2.1.0.json")
        driver = document["runs"][0]["tool"]["driver"]
        assert driver["name"] == "docker-security-scanner"
        assert driver["version"] == "9.9.9"

    def test_every_used_rule_is_declared(self) -> None:
        document = json.loads(render_sarif(_result()))
        declared = {rule["id"] for rule in document["runs"][0]["tool"]["driver"]["rules"]}
        assert declared == {"DF-002", "CP-001"}

    def test_results_carry_location_and_level(self) -> None:
        results = json.loads(render_sarif(_result()))["runs"][0]["results"]
        first = results[0]
        assert first["ruleId"] == "CP-001"
        assert first["level"] == "error"
        location = first["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "docker-compose.yml"
        assert location["region"]["startLine"] == 4
        assert first["properties"]["severity"] == "critical"

    def test_medium_and_low_become_warnings(self) -> None:
        result = _empty()
        result.add(
            Finding(
                rule_id="DF-014",
                title="Unpinned packages",
                severity=Severity.MEDIUM,
                category=Category.DOCKERFILE,
                message="m",
                location=Location(source="Dockerfile", line=1),
            )
        )
        document = json.loads(render_sarif(result))
        assert document["runs"][0]["results"][0]["level"] == "warning"

    def test_scan_errors_are_reported_as_notifications(self) -> None:
        result = _empty()
        result.errors.append("broken file")
        invocation = json.loads(render_sarif(result))["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        assert invocation["toolExecutionNotifications"][0]["message"]["text"] == "broken file"

    def test_clean_scan_is_successful_with_no_result(self) -> None:
        run = json.loads(render_sarif(_empty()))["runs"][0]
        assert run["results"] == []
        assert run["invocations"][0]["executionSuccessful"] is True


@pytest.mark.parametrize(
    "renderer", [render_console, render_json, render_markdown, render_sarif]
)
def test_every_renderer_handles_an_empty_result(renderer) -> None:
    assert renderer(ScanResult()).strip()
