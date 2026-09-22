"""Tests of the daemon scanner: one test per ``DM-`` rule."""

from __future__ import annotations

import json

import pytest

from src.daemon_scanner import DaemonScanner
from src.models import ScanResult, Severity
from tests.helpers import assert_no_rule, assert_rule, daemon_config, rule_ids


class TestDaemonScanner:
    def _scan(self, config: dict, **kwargs: object) -> ScanResult:
        return DaemonScanner().scan_document(config, **kwargs)  # type: ignore[arg-type]

    def test_hardened_daemon_configuration_is_clean(self) -> None:
        assert rule_ids(self._scan(daemon_config())) == []

    def test_scan_text_reads_a_json_document(self) -> None:
        text = json.dumps(daemon_config(hosts=["tcp://0.0.0.0:2375"]))
        result = DaemonScanner().scan_text(text, "/etc/docker/daemon.json")
        assert "DM-001" in rule_ids(result)

    def test_dm001_reports_a_tcp_api_socket(self) -> None:
        hosts = ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]
        finding = assert_rule(self._scan(daemon_config(hosts=hosts)), "DM-001")
        assert finding.severity is Severity.CRITICAL
        assert "tcp://0.0.0.0:2375" in finding.evidence

    def test_dm001_reports_disabled_tls(self) -> None:
        assert_rule(self._scan(daemon_config(tls=False)), "DM-001")
        assert_rule(self._scan(daemon_config(tlsverify=False)), "DM-001")

    def test_dm001_reports_a_tls_flag_from_the_command_line(self) -> None:
        config = daemon_config()
        del config["tls"]
        del config["tlsverify"]
        result = self._scan(config, flags=["--host=tcp://0.0.0.0:2376", "--tls=false"])
        assert_rule(result, "DM-001")

    def test_dm001_absent_for_a_unix_socket_with_tls(self) -> None:
        assert_no_rule(self._scan(daemon_config()), "DM-001")

    def test_dm002_reports_insecure_registries(self) -> None:
        config = daemon_config(**{"insecure-registries": ["registry.internal:5000"]})
        finding = assert_rule(self._scan(config), "DM-002")
        assert "registry.internal:5000" in finding.evidence

    def test_dm002_absent_without_insecure_registries(self) -> None:
        assert_no_rule(self._scan(daemon_config(**{"insecure-registries": []})), "DM-002")

    def test_dm003_reports_a_missing_no_new_privileges(self) -> None:
        config = daemon_config()
        del config["no-new-privileges"]
        assert_rule(self._scan(config), "DM-003")

    def test_dm004_reports_the_userland_proxy_default(self) -> None:
        config = daemon_config()
        del config["userland-proxy"]
        assert_rule(self._scan(config), "DM-004")

    def test_dm005_reports_a_disabled_live_restore(self) -> None:
        assert_rule(self._scan(daemon_config(**{"live-restore": False})), "DM-005")

    def test_dm006_reports_enabled_inter_container_communication(self) -> None:
        assert_rule(self._scan(daemon_config(icc=True)), "DM-006")

    def test_dm007_reports_a_missing_authorization_plugin(self) -> None:
        assert_rule(self._scan(daemon_config(**{"authorization-plugins": []})), "DM-007")

    def test_dm008_reports_a_missing_userns_remap(self) -> None:
        config = daemon_config()
        del config["userns-remap"]
        assert_rule(self._scan(config), "DM-008")

    def test_dm009_reports_a_log_driver_without_rotation(self) -> None:
        finding = assert_rule(self._scan(daemon_config(**{"log-opts": {}})), "DM-009")
        assert "json-file" in finding.message

    def test_dm009_absent_for_a_non_file_log_driver(self) -> None:
        config = daemon_config(**{"log-driver": "syslog"})
        del config["log-opts"]
        assert_no_rule(self._scan(config), "DM-009")

    def test_dm010_reports_disabled_iptables_management(self) -> None:
        assert_rule(self._scan(daemon_config(iptables=False)), "DM-010")

    def test_dm011_reports_unlimited_default_ulimits(self) -> None:
        config = daemon_config(
            **{"default-ulimits": {"nofile": {"Name": "nofile", "Soft": -1, "Hard": -1}}}
        )
        finding = assert_rule(self._scan(config), "DM-011")
        assert "nofile" in finding.evidence

    def test_dm011_absent_for_finite_ulimits(self) -> None:
        assert_no_rule(self._scan(daemon_config()), "DM-011")

    def test_dm012_reports_an_unconfined_seccomp_profile(self) -> None:
        assert_rule(self._scan(daemon_config(**{"seccomp-profile": "unconfined"})), "DM-012")

    def test_dm013_reports_a_credential_in_a_proxy_url(self) -> None:
        proxies = {"http-proxy": "http://build-bot:ci-token-9f2b41@proxy.internal:3128"}
        finding = assert_rule(self._scan(daemon_config(proxies=proxies)), "DM-013")
        assert "ci-token-9f2b41" not in finding.evidence
        assert "redacted" in finding.evidence

    def test_dm013_reports_a_credential_looking_key(self) -> None:
        config = daemon_config(**{"registry-password": "hunter2-hunter2"})
        assert_rule(self._scan(config), "DM-013")

    def test_dm013_absent_for_a_plain_proxy_url(self) -> None:
        config = daemon_config(proxies={"http-proxy": "http://proxy.internal:3128"})
        assert_no_rule(self._scan(config), "DM-013")

    def test_locations_report_the_json_key(self) -> None:
        text = json.dumps(daemon_config(**{"insecure-registries": ["r:5000"]}), indent=2)
        finding = assert_rule(DaemonScanner().scan_text(text, "daemon.json"), "DM-002")
        assert finding.location.path == "insecure-registries"
        assert finding.location.line > 0


class TestDaemonHostMode:
    def test_docker_info_output_is_scanned(self) -> None:
        info = {
            "LoggingDriver": "json-file",
            "LoggingDriverOpts": {},
            "InsecureRegistries": ["registry.internal:5000"],
            "LiveRestoreEnabled": False,
            "SecurityOptions": [],
            "Icc": True,
            "Plugins": {"Authorization": [], "Log": ["json-file"]},
        }
        found = rule_ids(DaemonScanner().scan_info(info, "docker info"))
        for rule_id in ("DM-002", "DM-005", "DM-006", "DM-007", "DM-008", "DM-009"):
            assert rule_id in found

    def test_fields_absent_from_docker_info_are_not_reported(self) -> None:
        """``docker info`` does not expose everything: no finding for silence."""
        info = {"LoggingDriver": "syslog", "Icc": False, "Plugins": {"Authorization": ["authz"]}}
        found = rule_ids(DaemonScanner().scan_info(info, "docker info"))
        assert "DM-004" not in found  # userland-proxy is not part of docker info
        assert "DM-009" not in found
        assert "DM-010" not in found

    def test_a_hardened_docker_info_is_quiet(self) -> None:
        info = {
            "LoggingDriver": "json-file",
            "LoggingDriverOpts": {"max-size": "10m", "max-file": "3"},
            "InsecureRegistries": [],
            "LiveRestoreEnabled": True,
            "SecurityOptions": ["name=userns", "name=no-new-privileges"],
            "Icc": False,
            "Plugins": {"Authorization": ["authz-broker"]},
        }
        assert rule_ids(DaemonScanner().scan_info(info, "docker info")) == []


class TestDaemonParsingErrors:
    def test_invalid_json_is_reported(self) -> None:
        with pytest.raises(ValueError, match="invalid JSON"):
            DaemonScanner().scan_text("{not json}", "daemon.json")

    def test_empty_document_is_reported(self) -> None:
        result = DaemonScanner().scan_text("", "daemon.json")
        assert result.errors
        assert result.findings == []

    def test_empty_mapping_is_reported(self) -> None:
        result = DaemonScanner().scan_document({}, "daemon.json")
        assert result.errors

    def test_ignore_and_min_severity_are_honoured(self) -> None:
        config = daemon_config(icc=True, **{"live-restore": False})
        del config["authorization-plugins"]  # so that DM-007 is expected
        scanner = DaemonScanner(ignore=["DM-006"], min_severity=Severity.MEDIUM)
        found = rule_ids(scanner.scan_document(config, "daemon.json"))
        assert "DM-006" not in found
        assert "DM-005" not in found  # DM-005 is LOW, below the threshold
        assert "DM-007" in found
