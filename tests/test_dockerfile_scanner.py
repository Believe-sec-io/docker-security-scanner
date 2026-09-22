"""Tests of the Dockerfile scanner: one test per ``DF-`` rule."""

from __future__ import annotations

import pytest

from src.dockerfile_scanner import DockerfileScanner
from src.models import ScanResult, Severity
from tests.helpers import assert_no_rule, assert_rule, rule_ids


class TestDockerfileScanner:
    """One test per ``DF-`` rule, plus the filters and the file entry point."""

    def _scan(self, text: str) -> ScanResult:
        return DockerfileScanner().scan_text(text, "Dockerfile")
    """One test per ``DF-`` rule, plus the filters and the file entry point."""

    def _scan(self, text: str) -> ScanResult:
        return DockerfileScanner().scan_text(text, "Dockerfile")

    def test_df001_reports_a_missing_user_instruction(self) -> None:
        finding = assert_rule(self._scan("FROM alpine:3.20\nCMD [\"true\"]\n"), "DF-001")
        assert finding.severity is Severity.HIGH

    def test_df001_absent_when_a_user_is_set(self) -> None:
        result = self._scan("FROM alpine:3.20\nUSER 10001\n")
        assert_no_rule(result, "DF-001")

    def test_df002_reports_an_explicit_root_user(self) -> None:
        assert_rule(self._scan("FROM alpine:3.20\nUSER root\n"), "DF-002")
        assert_rule(self._scan("FROM alpine:3.20\nUSER 0:0\n"), "DF-002")

    def test_df002_absent_for_an_unprivileged_user(self) -> None:
        assert_no_rule(self._scan("FROM alpine:3.20\nUSER app\n"), "DF-002")

    def test_df003_reports_an_unpinned_base_image(self) -> None:
        finding = assert_rule(self._scan("FROM ubuntu:latest\nUSER app\n"), "DF-003")
        assert "ubuntu:latest" in finding.evidence

    def test_df003_ignores_a_pinned_or_dynamic_reference(self) -> None:
        assert_no_rule(self._scan("FROM python:3.12.7\nUSER app\n"), "DF-003")
        assert_no_rule(self._scan("FROM alpine@sha256:abc\nUSER app\n"), "DF-003")
        assert_no_rule(self._scan("ARG VERSION\nFROM alpine:${VERSION}\nUSER app\n"), "DF-003")
        assert_no_rule(self._scan("FROM scratch\nCOPY app /app\nUSER app\n"), "DF-003")

    def test_df004_reports_a_remote_add(self) -> None:
        text = "FROM alpine:3.20\nADD https://example.com/app.tar.gz /tmp/\nUSER app\n"
        assert_rule(self._scan(text), "DF-004")

    def test_df004_absent_for_a_local_copy(self) -> None:
        text = "FROM alpine:3.20\nADD app.tar.gz /tmp/\nUSER app\n"
        assert_no_rule(self._scan(text), "DF-004")

    def test_df005_reports_a_pipe_to_shell(self) -> None:
        for command in (
            "curl -fsSL https://example.com/install.sh | sh",
            "wget -qO- https://example.com/get.py | python3",
        ):
            text = f"FROM alpine:3.20\nRUN {command}\nUSER app\n"
            assert_rule(self._scan(text), "DF-005")

    def test_df005_absent_for_a_plain_download(self) -> None:
        text = (
            "FROM alpine:3.20\n"
            "RUN curl -fsSL https://example.com/app.tar.gz -o /tmp/app.tar.gz\n"
            "USER app\n"
        )
        assert_no_rule(self._scan(text), "DF-005")

    def test_df006_reports_hardcoded_env_and_arg_secrets(self) -> None:
        for line in (
            "ENV DB_PASSWORD=hunter2-hunter2",
            "ARG NPM_TOKEN=npm_9f2b41c8deadbeef",
            "LABEL token=ghp_9f2b41c8deadbeef0123",
        ):
            assert_rule(self._scan(f"FROM alpine:3.20\n{line}\nUSER app\n"), "DF-006")

    def test_df006_never_leaks_the_secret_value(self) -> None:
        result = self._scan("FROM alpine:3.20\nENV DB_PASSWORD=hunter2-hunter2\nUSER app\n")
        finding = assert_rule(result, "DF-006")
        assert "hunter2" not in finding.evidence
        assert "redacted" in finding.evidence

    def test_df006_absent_for_interpolated_or_placeholder_values(self) -> None:
        text = (
            "FROM alpine:3.20\n"
            "ENV DB_PASSWORD=${DB_PASSWORD}\n"
            "ENV API_KEY=changeme\n"
            "USER app\n"
        )
        assert_no_rule(self._scan(text), "DF-006")

    def test_df007_reports_world_writable_permissions(self) -> None:
        for command in ("chmod 777 /app", "chmod -R 666 /data", "chmod o+w /etc/app.conf"):
            assert_rule(self._scan(f"FROM alpine:3.20\nRUN {command}\nUSER app\n"), "DF-007")

    def test_df007_absent_for_a_restrictive_mode(self) -> None:
        text = "FROM alpine:3.20\nRUN chmod 750 /app && chmod 600 /etc/app.conf\nUSER app\n"
        assert_no_rule(self._scan(text), "DF-007")

    def test_df008_reports_a_dirty_package_cache(self) -> None:
        text = "FROM alpine:3.20\nRUN apt-get update && apt-get install -y curl\nUSER app\n"
        assert_rule(self._scan(text), "DF-008")

    def test_df008_absent_when_the_cache_is_cleaned(self) -> None:
        text = (
            "FROM alpine:3.20\n"
            "RUN apt-get update && apt-get install -y curl \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
            "USER app\n"
        )
        assert_no_rule(self._scan(text), "DF-008")

    def test_df008_accepts_apk_no_cache(self) -> None:
        text = "FROM alpine:3.20\nRUN apk add --no-cache curl=8.9.1-r0\nUSER app\n"
        assert_no_rule(self._scan(text), "DF-008")

    def test_df009_reports_sudo(self) -> None:
        assert_rule(self._scan("FROM alpine:3.20\nRUN sudo apt-get update\nUSER app\n"), "DF-009")

    def test_df010_reports_a_sensitive_exposed_port(self) -> None:
        result = self._scan("FROM alpine:3.20\nEXPOSE 22 8080\nUSER app\n")
        finding = assert_rule(result, "DF-010")
        assert "22" in finding.evidence

    def test_df010_handles_a_port_range_and_protocol(self) -> None:
        # 20-25 includes the SSH port, 6379/tcp is Redis.
        assert_rule(self._scan("FROM alpine:3.20\nEXPOSE 20-25\nUSER app\n"), "DF-010")
        assert_rule(self._scan("FROM alpine:3.20\nEXPOSE 6379/tcp\nUSER app\n"), "DF-010")

    def test_df010_absent_for_an_application_port(self) -> None:
        assert_no_rule(self._scan("FROM alpine:3.20\nEXPOSE 8080\nUSER app\n"), "DF-010")

    def test_df011_reports_a_missing_healthcheck(self) -> None:
        assert_rule(self._scan("FROM alpine:3.20\nUSER app\n"), "DF-011")

    def test_df011_absent_when_a_healthcheck_exists(self) -> None:
        text = 'FROM alpine:3.20\nHEALTHCHECK --interval=30s CMD ["true"]\nUSER app\n'
        assert_no_rule(self._scan(text), "DF-011")

    def test_df011_reports_a_disabled_healthcheck(self) -> None:
        text = "FROM alpine:3.20\nHEALTHCHECK NONE\nUSER app\n"
        finding = assert_rule(self._scan(text), "DF-011")
        assert "disabled" in finding.message

    def test_df012_reports_an_ssh_server(self) -> None:
        for package in ("openssh-server", "openssh-server=1:9.2p1-2", "dropbear"):
            text = f"FROM alpine:3.20\nRUN apt-get install -y {package}\nUSER app\n"
            assert_rule(self._scan(text), "DF-012")

    def test_df013_reports_credential_files_in_a_copy(self) -> None:
        for source in (".env", "keys/id_rsa", "certs/server.pem", ".aws/credentials", ".git/config"):
            text = f"FROM alpine:3.20\nCOPY {source} /app/\nUSER app\n"
            assert_rule(self._scan(text), "DF-013")

    def test_df013_absent_for_application_code(self) -> None:
        text = "FROM alpine:3.20\nCOPY app /app\nCOPY requirements.txt /app/\nUSER app\n"
        assert_no_rule(self._scan(text), "DF-013")

    def test_df014_reports_unpinned_packages(self) -> None:
        text = "FROM alpine:3.20\nRUN pip install flask requests\nUSER app\n"
        finding = assert_rule(self._scan(text), "DF-014")
        assert "flask" in finding.evidence

    def test_df014_absent_when_packages_are_pinned_or_from_a_file(self) -> None:
        text = (
            "FROM alpine:3.20\n"
            "RUN apt-get install -y curl=8.9.1-0ubuntu1\n"
            "RUN pip install -r requirements.txt\n"
            "USER app\n"
        )
        assert_no_rule(self._scan(text), "DF-014")

    def test_df015_reports_shell_form_commands(self) -> None:
        assert_rule(self._scan('FROM alpine:3.20\nUSER app\nCMD python app.py\n'), "DF-015")
        assert_rule(self._scan('FROM alpine:3.20\nUSER app\nENTRYPOINT sh start.sh\n'), "DF-015")

    def test_df015_absent_for_the_exec_form(self) -> None:
        text = 'FROM alpine:3.20\nUSER app\nENTRYPOINT ["python", "app.py"]\n'
        assert_no_rule(self._scan(text), "DF-015")


class TestDockerfileFilters:
    """``--ignore`` and ``--severity`` must work on every rule."""

    def test_ignore_silences_a_single_rule(self) -> None:
        text = "FROM alpine:3.20\nUSER root\n"
        scanner = DockerfileScanner(ignore=["DF-002"])
        assert "DF-002" not in rule_ids(scanner.scan_text(text, "Dockerfile"))

    def test_unknown_rule_id_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown rule id"):
            DockerfileScanner(ignore=["DF-999"])

    def test_min_severity_filters_out_lower_severities(self) -> None:
        text = "FROM alpine:3.20\nUSER root\nRUN chmod 777 /app\n"
        scanner = DockerfileScanner(min_severity=Severity.HIGH)
        # DF-002 is HIGH, DF-007 is MEDIUM and DF-011 is LOW.
        assert rule_ids(scanner.scan_text(text, "Dockerfile")) == ["DF-002"]

    def test_min_severity_keeps_every_severity_above_the_threshold(self) -> None:
        text = "FROM alpine:3.20\nUSER app\n"
        low = DockerfileScanner(min_severity=Severity.LOW).scan_text(text, "Dockerfile")
        assert "DF-011" in rule_ids(low)
        medium = DockerfileScanner(min_severity=Severity.MEDIUM).scan_text(text, "Dockerfile")
        assert "DF-011" not in rule_ids(medium)


class TestDockerfileFileEntryPoint:
    def test_scan_file_reads_an_utf8_file(self, tmp_path) -> None:
        target = tmp_path / "Dockerfile"
        target.write_text("FROM alpine:latest\nUSER root\n", encoding="utf-8")
        result = DockerfileScanner().scan_file(str(target))
        assert result.target == str(target)
        assert result.sources == [str(target)]
        assert "DF-002" in rule_ids(result)

    def test_scan_reports_an_empty_dockerfile(self) -> None:
        result = DockerfileScanner().scan_text("# only a comment\n", "Dockerfile")
        assert result.errors
        assert result.findings == []
