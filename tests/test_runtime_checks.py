"""Tests posture runtime : analyse d'un docker inspect simule (sans demon)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import runtime_checks  # noqa: E402


def make_inspect(**overrides):
    """Fabrique un faux docker inspect minimal (conteneur durci par defaut)."""
    host = {
        "Privileged": False,
        "PidMode": "",
        "NetworkMode": "bridge",
        "CapAdd": [],
        "Memory": 536870912,
        "NanoCpus": 1000000000,
        "ReadonlyRootfs": True,
        "SecurityOpt": ["seccomp=/path/to/profile.json"],
        "RestartPolicy": {"Name": "no"},
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m"}},
        "PortBindings": {},
    }
    host.update(overrides.pop("HostConfig", {}))
    data = {
        "Name": "/demo",
        "Id": "abc123",
        "Created": "2024-01-01",
        "Config": {"Image": "demo:1.0", "User": "10001",
                   "Healthcheck": {"Test": ["CMD", "true"]}},
        "State": {"Status": "running", "RestartCount": 0},
        "HostConfig": host,
        "Mounts": [],
    }
    data.update(overrides)
    return data


class RuntimeChecksTests(unittest.TestCase):
    """Chaque posture dangereuse doit lever sa regle DS-RT-*."""

    def test_clean_container_has_no_high(self):
        findings = runtime_checks.analyze_container(make_inspect())
        bad = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        self.assertEqual([], [f.rule_id for f in bad])

    def test_privileged_pid_host_and_caps(self):
        data = make_inspect(HostConfig={"Privileged": True, "PidMode": "host",
                                       "CapAdd": ["SYS_ADMIN"]})
        ids = {f.rule_id for f in runtime_checks.analyze_container(data)}
        self.assertIn("DS-RT-001", ids)
        self.assertIn("DS-RT-002", ids)
        self.assertIn("DS-RT-003", ids)

    def test_no_limits_socket_root_and_writable(self):
        data = make_inspect(
            HostConfig={"Memory": 0, "NanoCpus": 0, "ReadonlyRootfs": False,
                       "SecurityOpt": []},
            Mounts=[{"Source": "/var/run/docker.sock",
                     "Destination": "/var/run/docker.sock"}],
        )
        data["Config"] = {"Image": "demo:1.0", "User": ""}
        ids = {f.rule_id for f in runtime_checks.analyze_container(data)}
        self.assertIn("DS-RT-004", ids)
        self.assertIn("DS-RT-005", ids)
        self.assertIn("DS-RT-006", ids)
        self.assertIn("DS-RT-007", ids)
        self.assertIn("DS-RT-008", ids)

    def test_sensitive_mount_and_published_port(self):
        data = make_inspect(
            HostConfig={"PortBindings": {"5432/tcp": [{"HostPort": "5432"}]}},
            Mounts=[{"Source": "/etc", "Destination": "/host-etc", "RW": True}],
        )
        ids = {f.rule_id for f in runtime_checks.analyze_container(data)}
        self.assertIn("DS-RT-009", ids)
        self.assertIn("DS-RT-010", ids)

    def test_restart_without_health_and_log_rotation(self):
        data = make_inspect(
            HostConfig={"RestartPolicy": {"Name": "always"},
                       "LogConfig": {"Type": "json-file", "Config": {}}},
        )
        data["Config"] = {"Image": "demo:1.0", "User": "10001"}
        ids = {f.rule_id for f in runtime_checks.analyze_container(data)}
        self.assertIn("DS-RT-011", ids)
        self.assertIn("DS-RT-012", ids)

    def test_metadata_summary(self):
        meta = runtime_checks.container_metadata(make_inspect())
        self.assertEqual("demo", meta["name"])
        self.assertTrue(meta["read_only_rootfs"])


if __name__ == "__main__":
    unittest.main()
