"""Tests of the container scanner: one test per ``CT-`` rule."""

from __future__ import annotations

import json

import pytest

from src.container_scanner import ContainerScanner
from src.models import ScanResult, Severity
from tests.helpers import assert_no_rule, assert_rule, docker_inspect, rule_ids

#: A read-write bind mount of the Docker socket, as ``docker inspect`` reports it.
SOCKET_MOUNT = [
    {
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "RW": True,
    }
]


class TestContainerScanner:
    def _scan(self, document: object, **kwargs: object) -> ScanResult:
        return ContainerScanner().scan_document(document, **kwargs)  # type: ignore[arg-type]

    def test_hardened_container_is_clean(self) -> None:
        assert rule_ids(self._scan(docker_inspect())) == []

    def test_scan_text_reads_a_json_document(self) -> None:
        text = json.dumps(docker_inspect(host={"Privileged": True}))
        result = ContainerScanner().scan_text(text, "docker-inspect.json")
        assert "CT-001" in rule_ids(result)

    def test_ct001_reports_a_privileged_container(self) -> None:
        finding = assert_rule(self._scan(docker_inspect(host={"Privileged": True})), "CT-001")
        assert finding.severity is Severity.CRITICAL

    def test_ct002_reports_a_docker_socket_mount(self) -> None:
        assert_rule(self._scan(docker_inspect(mounts=SOCKET_MOUNT)), "CT-002")

    def test_ct002_also_reads_host_config_binds(self) -> None:
        document = docker_inspect(host={"Binds": ["/var/run/docker.sock:/var/run/docker.sock:rw"]})
        assert_rule(self._scan(document), "CT-002")

    @pytest.mark.parametrize(
        ("key", "rule_id"),
        [("NetworkMode", "CT-003"), ("PidMode", "CT-004"), ("IpcMode", "CT-005")],
    )
    def test_ct003_to_ct005_report_the_host_namespaces(self, key: str, rule_id: str) -> None:
        assert_rule(self._scan(docker_inspect(host={key: "host"})), rule_id)

    def test_ct003_to_ct005_absent_for_private_namespaces(self) -> None:
        document = docker_inspect(host={"PidMode": "container:other", "IpcMode": "private"})
        result = self._scan(document)
        assert_no_rule(result, "CT-003")
        assert_no_rule(result, "CT-004")
        assert_no_rule(result, "CT-005")

    def test_ct006_reports_a_root_user(self) -> None:
        for user in ("", "root", "0", "0:0"):
            assert_rule(self._scan(docker_inspect(user=user)), "CT-006")

    def test_ct007_reports_a_writable_root_filesystem(self) -> None:
        assert_rule(self._scan(docker_inspect(host={"ReadonlyRootfs": False})), "CT-007")

    def test_ct008_reports_dangerous_capabilities(self) -> None:
        finding = assert_rule(self._scan(docker_inspect(host={"CapAdd": ["SYS_ADMIN"]})), "CT-008")
        assert "SYS_ADMIN" in finding.evidence

    def test_ct008_absent_for_a_narrow_capability(self) -> None:
        document = docker_inspect(host={"CapAdd": ["NET_BIND_SERVICE"]})
        assert_no_rule(self._scan(document), "CT-008")

    def test_ct009_reports_a_missing_no_new_privileges(self) -> None:
        document = docker_inspect(host={"SecurityOpt": ["apparmor=docker-default"]})
        assert_rule(self._scan(document), "CT-009")

    def test_ct010_reports_an_unconfined_seccomp_profile(self) -> None:
        document = docker_inspect(
            host={"SecurityOpt": ["seccomp=unconfined", "no-new-privileges:true"]}
        )
        assert_rule(self._scan(document), "CT-010")

    def test_ct011_reports_a_missing_or_disabled_healthcheck(self) -> None:
        assert_rule(self._scan(docker_inspect(healthcheck=None)), "CT-011")
        disabled = {"Test": ["NONE"]}
        finding = assert_rule(self._scan(docker_inspect(healthcheck=disabled)), "CT-011")
        assert "disables" in finding.message

    def test_ct012_reports_a_mutable_image(self) -> None:
        for image in ("myapp:latest", "myapp", "ghcr.io/a/b:stable"):
            assert_rule(self._scan(docker_inspect(image=image)), "CT-012")

    def test_ct012_absent_for_a_digest_pinned_image(self) -> None:
        image = "ghcr.io/example/api@sha256:6b86b273ff34fce19d6b804eff5a3f57"
        assert_no_rule(self._scan(docker_inspect(image=image)), "CT-012")

    def test_ct013_reports_literal_secrets_and_never_leaks_them(self) -> None:
        document = docker_inspect(env=["PATH=/usr/bin", "DB_PASSWORD=hunter2-hunter2"])
        finding = assert_rule(self._scan(document), "CT-013")
        assert finding.severity is Severity.CRITICAL
        assert "hunter2" not in finding.evidence

    def test_ct013_absent_for_interpolations(self) -> None:
        document = docker_inspect(env=["DB_PASSWORD=${DB_PASSWORD}", "PORT=8080"])
        assert_no_rule(self._scan(document), "CT-013")

    def test_ct014_reports_missing_resource_limits(self) -> None:
        document = docker_inspect(host={"Memory": 0, "NanoCpus": 0, "CpuShares": 0})
        assert_rule(self._scan(document), "CT-014")

    def test_ct015_reports_missing_mandatory_access_control(self) -> None:
        document = docker_inspect(host={"SecurityOpt": ["no-new-privileges:true"]})
        assert_rule(self._scan(document), "CT-015")

    def test_ct015_absent_when_a_profile_is_applied(self) -> None:
        assert_no_rule(self._scan(docker_inspect()), "CT-015")

    def test_ct016_reports_a_sensitive_host_path_mounted_read_write(self) -> None:
        mounts = [{"Type": "bind", "Source": "/", "Destination": "/host", "RW": True}]
        finding = assert_rule(self._scan(docker_inspect(mounts=mounts)), "CT-016")
        assert "read-write" in finding.message

    def test_ct016_absent_for_read_only_and_safe_mounts(self) -> None:
        mounts = [
            {"Type": "bind", "Source": "/etc", "Destination": "/etc", "RW": False},
            {"Type": "bind", "Source": "/etc/hosts", "Destination": "/etc/hosts", "RW": True},
            {"Type": "volume", "Source": "api-data", "Destination": "/data", "RW": True},
        ]
        assert_no_rule(self._scan(docker_inspect(mounts=mounts)), "CT-016")

    def test_ct016_does_not_duplicate_the_docker_socket(self) -> None:
        document = docker_inspect(mounts=SOCKET_MOUNT)
        document[0]["HostConfig"]["Binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        result = self._scan(document)
        assert len([f for f in result.findings if f.rule_id == "CT-002"]) == 1
        assert_no_rule(result, "CT-016")

    def test_ct017_reports_a_host_device(self) -> None:
        devices = [{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda"}]
        finding = assert_rule(self._scan(docker_inspect(host={"Devices": devices})), "CT-017")
        assert "/dev/sda" in finding.message

    def test_several_containers_are_all_checked(self) -> None:
        first = docker_inspect(name="api", host={"Privileged": True})[0]
        second = docker_inspect(name="worker", user="root")[0]
        result = self._scan([first, second])
        assert len([f for f in result.findings if f.rule_id == "CT-001"]) == 1
        assert len([f for f in result.findings if f.rule_id == "CT-006"]) == 1

    def test_locations_name_the_container(self) -> None:
        finding = assert_rule(self._scan(docker_inspect(name="api", user="root")), "CT-006")
        assert finding.location.path == "api"


class TestContainerParsingErrors:
    def test_invalid_json_is_reported(self) -> None:
        with pytest.raises(ValueError, match="invalid JSON"):
            ContainerScanner().scan_text("][", "docker-inspect.json")

    def test_document_without_container_object_is_reported(self) -> None:
        result = ContainerScanner().scan_document({"not": "a container"}, "docker-inspect.json")
        assert result.errors
        assert result.findings == []

    def test_ignore_and_min_severity_are_honoured(self) -> None:
        document = docker_inspect(user="root", host={"Privileged": True})
        scanner = ContainerScanner(ignore=["CT-006"], min_severity=Severity.MEDIUM)
        found = rule_ids(scanner.scan_document(document, "docker-inspect.json"))
        assert "CT-006" not in found
        assert "CT-001" in found
