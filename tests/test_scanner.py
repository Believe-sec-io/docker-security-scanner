"""Tests of the scan orchestrator (kind detection, directories, dispatch)."""

from __future__ import annotations

import json

import pytest

from src.models import Severity
from src.scanner import CONCRETE_KINDS, Scanner, TARGET_KINDS, detect_kind
from tests.helpers import daemon_config, docker_inspect, rule_ids


class TestKindDetection:
    @pytest.mark.parametrize(
        "name", ["Dockerfile", "dockerfile", "Dockerfile.dev", "app.dockerfile", "Containerfile"]
    )
    def test_dockerfile_names(self, name: str) -> None:
        assert detect_kind(name) == "dockerfile"

    @pytest.mark.parametrize(
        "name",
        [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            "docker-compose.insecure.yml",
        ],
    )
    def test_compose_names(self, name: str) -> None:
        assert detect_kind(name) == "compose"

    @pytest.mark.parametrize("name", ["daemon.json", "daemon.json.secure", "dockerd.json"])
    def test_daemon_names(self, name: str) -> None:
        assert detect_kind(name) == "daemon"

    @pytest.mark.parametrize(
        "name", ["docker-inspect.json", "inspect.json", "docker-inspect.insecure.json"]
    )
    def test_container_names(self, name: str) -> None:
        assert detect_kind(name) == "container"

    @pytest.mark.parametrize("name", ["docker-info.json", "info.json", "docker-info.insecure.json"])
    def test_info_names(self, name: str) -> None:
        assert detect_kind(name) == "info"

    def test_unknown_name_is_reported(self) -> None:
        assert detect_kind("notes.txt") == "unknown"

    def test_content_detection_for_a_nameless_document(self) -> None:
        assert detect_kind("", "FROM alpine:3.20\n") == "dockerfile"
        assert detect_kind("", "services:\n  api: {}\n") == "compose"
        assert detect_kind("", '{"key": "value"}') == "unknown"

    def test_concrete_kinds_are_exposed_for_the_cli(self) -> None:
        assert TARGET_KINDS[0] == "auto"
        assert CONCRETE_KINDS == "dockerfile|compose|daemon|info|container"


class TestScannerDispatch:
    def test_scan_file_dispatches_on_the_name(self, tmp_path) -> None:
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
        assert "DF-003" in rule_ids(Scanner().scan(str(dockerfile)))

    def test_scan_file_honours_an_explicit_kind(self, tmp_path) -> None:
        target = tmp_path / "config.txt"
        target.write_text("FROM alpine:latest\nUSER app\n", encoding="utf-8")
        assert "DF-003" in rule_ids(Scanner().scan(str(target), kind="dockerfile"))

    def test_unknown_kind_is_reported(self, tmp_path) -> None:
        target = tmp_path / "notes.txt"
        target.write_text("hello\n", encoding="utf-8")
        result = Scanner().scan(str(target))
        assert result.errors
        assert "cannot tell what this file is" in result.errors[0]

    def test_missing_file_is_reported(self) -> None:
        assert Scanner().scan("does-not-exist/Dockerfile").errors

    def test_scan_text_requires_a_concrete_kind(self) -> None:
        assert Scanner().scan_text("FROM alpine\n", "auto").errors

    def test_scan_stdin_text_detects_the_kind(self) -> None:
        result = Scanner().scan_stdin_text("FROM ubuntu:latest\nUSER app\n", source_name="<stdin>")
        assert "<stdin>" in result.sources
        assert "DF-003" in rule_ids(result)

    def test_malformed_yaml_is_reported_as_an_error(self) -> None:
        result = Scanner().scan_text("services: [1,\n", "compose", "docker-compose.yml")
        assert result.errors

    def test_info_kind_uses_the_daemon_scanner(self) -> None:
        text = json.dumps({"InsecureRegistries": ["registry.internal:5000"], "Icc": True})
        assert "DM-002" in rule_ids(Scanner().scan_text(text, "info", "docker-info.json"))


class TestScannerOverrides:
    def test_ignore_is_applied_by_every_scanner(self, tmp_path) -> None:
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
        result = Scanner(ignore=["DF-003"], min_severity=Severity.INFO).scan(str(dockerfile))
        assert "DF-003" not in rule_ids(result)
        assert "DF-002" in rule_ids(result)

    def test_an_unknown_ignored_rule_fails_immediately(self) -> None:
        with pytest.raises(ValueError, match="unknown rule id"):
            Scanner(ignore=["XX-001"])

    def test_min_severity_is_applied_by_every_scanner(self, tmp_path) -> None:
        target = tmp_path / "docker-compose.yml"
        target.write_text("services:\n  api:\n    image: app:latest\n    privileged: true\n")
        result = Scanner(min_severity=Severity.CRITICAL).scan(str(target))
        assert rule_ids(result) == ["CP-001"]


class TestDirectoryScan:
    def _project(self, tmp_path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  api:\n    privileged: true\n", encoding="utf-8"
        )
        (tmp_path / "daemon.json").write_text(json.dumps(daemon_config(icc=True)), encoding="utf-8")
        (tmp_path / "inspect.json").write_text(
            json.dumps(docker_inspect(user="root")), encoding="utf-8"
        )
        (tmp_path / "notes.txt").write_text("not a docker file\n", encoding="utf-8")
        ignored = tmp_path / "node_modules"
        ignored.mkdir()
        (ignored / "docker-compose.yml").write_text(
            "services:\n  api:\n    privileged: true\n", encoding="utf-8"
        )

    def test_directory_scan_aggregates_every_source(self, tmp_path) -> None:
        self._project(tmp_path)
        result = Scanner().scan(str(tmp_path))
        assert len(result.sources) == 4
        assert {"DF-003", "CP-001", "DM-006", "CT-006"} <= set(rule_ids(result))
        assert result.errors == []

    def test_ignored_directories_are_skipped(self, tmp_path) -> None:
        self._project(tmp_path)
        found = Scanner().find_targets(str(tmp_path))
        assert not any("node_modules" in path for path in found)
        assert len(found) == 4

    def test_an_empty_directory_is_reported(self, tmp_path) -> None:
        result = Scanner().scan(str(tmp_path))
        assert result.errors
        assert "no Docker configuration file found" in result.errors[0]

    def test_findings_are_de_duplicated_per_source(self, tmp_path) -> None:
        # Both files describe the same insecure service: the findings are not
        # de-duplicated across sources (they are two different files), but a
        # rule is never reported twice for the same file.
        content = "services:\n  api:\n    image: app:1.0\n    privileged: true\n"
        (tmp_path / "docker-compose.yml").write_text(content, encoding="utf-8")
        (tmp_path / "compose.yml").write_text(content, encoding="utf-8")
        result = Scanner().scan(str(tmp_path))
        assert len({finding.location.source for finding in result.findings}) == 2
        per_file_and_rule: dict[tuple[str, str], int] = {}
        for finding in result.findings:
            key = (finding.rule_id, finding.location.source)
            per_file_and_rule[key] = per_file_and_rule.get(key, 0) + 1
        assert all(count == 1 for count in per_file_and_rule.values())

    def test_size_limit_is_reported(self, tmp_path, monkeypatch) -> None:
        import src.scanner as scanner_module

        target = tmp_path / "Dockerfile"
        target.write_text("FROM alpine:latest\n", encoding="utf-8")
        monkeypatch.setattr(scanner_module, "MAX_FILE_BYTES", 4)
        result = Scanner().scan(str(target))
        assert result.errors
        assert "larger than" in result.errors[0]
