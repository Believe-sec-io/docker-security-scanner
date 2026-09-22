"""Tests of the Compose scanner: one test per ``CP-`` rule."""

from __future__ import annotations

import pytest
import yaml

from src.compose_scanner import ComposeScanner
from src.models import ScanResult, Severity
from tests.helpers import assert_no_rule, assert_rule, compose_service, rule_ids


def compose(*services: str, body: str = "") -> str:
    """Build a Compose document from already indented service blocks."""
    blocks = "\n".join(services)
    return f"services:\n{blocks}\n{body}"


def service(name: str, **overrides: object) -> str:
    """Render one service, starting from the hardened reference.

    The hardened service is a plain mapping dumped as YAML, so a test only
    states the field it wants to break (``service("api", privileged=True)``).
    """
    block = {name: compose_service(**overrides)}
    dumped = yaml.safe_dump(block, default_flow_style=False, sort_keys=False)
    return "\n".join(f"  {line}" for line in dumped.splitlines())


class TestComposeScanner:
    def _scan(self, text: str) -> ScanResult:
        return ComposeScanner().scan_text(text, "docker-compose.yml")

    def test_hardened_service_is_clean(self) -> None:
        assert rule_ids(self._scan(compose(service("api")))) == []

    def test_cp001_reports_a_privileged_service(self) -> None:
        finding = assert_rule(self._scan(compose(service("api", privileged=True))), "CP-001")
        assert finding.severity is Severity.CRITICAL

    def test_cp002_reports_a_docker_socket_mount(self) -> None:
        text = compose(service("api", volumes=["/var/run/docker.sock:/var/run/docker.sock"]))
        assert_rule(self._scan(text), "CP-002")

    def test_cp003_reports_the_host_network_mode(self) -> None:
        assert_rule(self._scan(compose(service("api", network_mode="host"))), "CP-003")

    @pytest.mark.parametrize(("key", "rule_id"), [("pid", "CP-004"), ("ipc", "CP-005")])
    def test_cp004_and_cp005_report_the_host_namespaces(self, key: str, rule_id: str) -> None:
        assert_rule(self._scan(compose(service("api", **{key: "host"}))), rule_id)

    def test_cp004_and_cp005_absent_for_private_namespaces(self) -> None:
        result = self._scan(compose(service("api", pid="container:other", ipc="private")))
        assert_no_rule(result, "CP-004")
        assert_no_rule(result, "CP-005")

    def test_cp006_reports_dangerous_capabilities(self) -> None:
        finding = assert_rule(self._scan(compose(service("api", cap_add=["SYS_ADMIN"]))), "CP-006")
        assert "SYS_ADMIN" in finding.evidence

    def test_cp006_absent_for_a_narrow_capability(self) -> None:
        text = compose(service("api", cap_add=["NET_BIND_SERVICE"]))
        assert_no_rule(self._scan(text), "CP-006")

    def test_cp007_reports_a_disabled_mac_profile(self) -> None:
        for option in ("seccomp:unconfined", "apparmor:unconfined", "label:disable"):
            text = compose(service("api", security_opt=[option]))
            assert_rule(self._scan(text), "CP-007")

    def test_cp008_reports_a_missing_no_new_privileges(self) -> None:
        assert_rule(self._scan(compose(service("api", security_opt=[]))), "CP-008")

    def test_cp008_absent_when_no_new_privileges_is_true(self) -> None:
        assert_no_rule(self._scan(compose(service("api"))), "CP-008")

    def test_cp009_reports_a_sensitive_host_path(self) -> None:
        text = compose(service("api", volumes=["/:/host", "/etc:/host-etc"]))
        finding = assert_rule(self._scan(text), "CP-009")
        assert finding.severity is Severity.HIGH

    def test_cp009_absent_for_a_read_only_or_relative_mount(self) -> None:
        text = compose(service("api", volumes=["./data:/data", "/etc/nginx:/conf:ro"]))
        assert_no_rule(self._scan(text), "CP-009")

    def test_cp010_reports_a_literal_secret_in_the_environment(self) -> None:
        text = compose(service("api", environment={"DB_PASSWORD": "hunter2-hunter2"}))
        finding = assert_rule(self._scan(text), "CP-010")
        assert "hunter2" not in finding.evidence

    def test_cp010_absent_for_interpolations_and_secret_paths(self) -> None:
        text = compose(
            service(
                "api",
                environment={"DB_PASSWORD": "${DB_PASSWORD}", "PASSWORD_FILE": "/run/secrets/x"},
            )
        )
        assert_no_rule(self._scan(text), "CP-010")

    def test_cp010_supports_the_list_form(self) -> None:
        text = compose(service("api", environment=["DB_PASSWORD=hunter2-hunter2", "PORT=8080"]))
        assert_rule(self._scan(text), "CP-010")

    def test_cp011_reports_a_datastore_port_published_everywhere(self) -> None:
        finding = assert_rule(self._scan(compose(service("api", ports=["5432:5432"]))), "CP-011")
        assert "5432" in finding.evidence

    def test_cp011_absent_for_loopback_or_application_ports(self) -> None:
        text = compose(service("api", ports=["127.0.0.1:5432:5432", "8080:8080"]))
        assert_no_rule(self._scan(text), "CP-011")

    def test_cp012_reports_missing_resource_limits(self) -> None:
        text = compose(service("api", mem_limit=None, cpus=None, pids_limit=None))
        assert_rule(self._scan(text), "CP-012")

    def test_cp013_reports_a_writable_root_filesystem(self) -> None:
        assert_rule(self._scan(compose(service("api", read_only=False))), "CP-013")

    def test_cp014_reports_a_root_user(self) -> None:
        for value in ("root", "0", "0:0"):
            text = compose(service("api", user=value))
            assert_rule(self._scan(text), "CP-014")

    def test_cp014_absent_for_an_unprivileged_user(self) -> None:
        assert_no_rule(self._scan(compose(service("api"))), "CP-014")

    def test_cp015_reports_a_missing_healthcheck(self) -> None:
        assert_rule(self._scan(compose(service("api", healthcheck=None))), "CP-015")

    def test_cp016_reports_a_mutable_image(self) -> None:
        for image in ("myapp:latest", "myapp", "ghcr.io/a/b:stable"):
            text = compose(service("api", image=image))
            assert_rule(self._scan(text), "CP-016")

    def test_cp016_absent_for_a_digest_pinned_image(self) -> None:
        text = compose(service("api", image="ghcr.io/example/api@sha256:abc"))
        assert_no_rule(self._scan(text), "CP-016")

    def test_every_service_is_checked(self) -> None:
        text = compose(
            service("api", privileged=True),
            service("worker", privileged=True),
        )
        assert len([f for f in self._scan(text).findings if f.rule_id == "CP-001"]) == 2

    def test_locations_point_at_the_service(self) -> None:
        finding = assert_rule(self._scan(compose(service("api", privileged=True))), "CP-001")
        assert "services.api" in finding.location.display()
        assert finding.location.line > 0


class TestComposeParsingErrors:
    def test_invalid_yaml_is_reported_as_a_value_error(self) -> None:
        with pytest.raises(ValueError, match="invalid YAML"):
            ComposeScanner().scan_text("services: [1,\n", "docker-compose.yml")

    def test_document_without_services_is_reported(self) -> None:
        result = ComposeScanner().scan_text("version: '3'\n", "docker-compose.yml")
        assert result.errors
        assert result.findings == []

    def test_services_must_be_a_mapping(self) -> None:
        result = ComposeScanner().scan_text("services: []\n", "docker-compose.yml")
        assert result.errors

    def test_scanner_accepts_ignore_and_min_severity(self) -> None:
        text = compose(service("api", privileged=True, read_only=False))
        scanner = ComposeScanner(ignore=["CP-001"], min_severity=Severity.LOW)
        found = rule_ids(scanner.scan_text(text, "docker-compose.yml"))
        assert "CP-001" not in found
        assert "CP-013" in found
