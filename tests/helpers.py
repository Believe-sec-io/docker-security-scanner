"""Shared helpers for the test suite.

The scanners are pure functions of a text or of a parsed document, so the tests
build their inputs inline. The helpers below keep those inputs short and make
the intent of a test obvious (``docker_inspect(user="root")`` reads better than
a 40-line dictionary).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.models import ScanResult

#: Repository root, useful for the tests that read the sample files.
ROOT = Path(__file__).resolve().parent.parent

#: Directory holding the insecure/hardened sample configurations.
EXAMPLES = ROOT / "examples"

#: Sentinel distinguishing "keep the default" from "set this field to null".
UNSET: Any = object()


def rule_ids(result: ScanResult) -> List[str]:
    """Return the sorted, de-duplicated rule ids found in ``result``."""
    return sorted({finding.rule_id for finding in result.findings})


def finding_for(result: ScanResult, rule_id: str) -> List[Any]:
    """Return every finding of ``result`` that belongs to ``rule_id``."""
    return [finding for finding in result.findings if finding.rule_id == rule_id]


def assert_rule(result: ScanResult, rule_id: str) -> Any:
    """Assert that ``rule_id`` was reported and return its first finding."""
    matches = finding_for(result, rule_id)
    assert matches, f"{rule_id} was not reported (got: {rule_ids(result)})"
    return matches[0]


def assert_no_rule(result: ScanResult, rule_id: str) -> None:
    """Assert that ``rule_id`` was not reported."""
    matches = finding_for(result, rule_id)
    assert not matches, f"{rule_id} should not have been reported: {matches[0].message}"


def docker_inspect(
    *,
    name: str = "api",
    user: str = "10001:10001",
    image: str = "ghcr.io/example/api:1.4.2",
    env: Any = UNSET,
    healthcheck: Any = UNSET,
    host: Optional[Dict[str, Any]] = None,
    mounts: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build a hardened ``docker inspect`` document, then apply the overrides.

    Every parameter defaults to the secure value, so a test only has to describe
    the one field it wants to break: ``docker_inspect(host={"Privileged": True})``.
    ``UNSET`` is the sentinel that distinguishes "keep the secure default" from
    "set this field to null", which ``docker inspect`` reports for a container
    without a healthcheck.
    """
    host_config: Dict[str, Any] = {
        "Privileged": False,
        "NetworkMode": "bridge",
        "PidMode": "",
        "IpcMode": "private",
        "ReadonlyRootfs": True,
        "CapAdd": [],
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true", "apparmor=docker-default"],
        "Memory": 536870912,
        "NanoCpus": 1000000000,
        "CpuShares": 512,
        "Binds": [],
        "Devices": [],
    }
    host_config.update(host or {})

    config: Dict[str, Any] = {
        "User": user,
        "Image": image,
        "Env": ["PATH=/usr/local/bin", "DB_PASSWORD=${DB_PASSWORD}"] if env is UNSET else env,
        "Healthcheck": (
            {"Test": ["CMD", "true"], "Interval": 30000000000}
            if healthcheck is UNSET
            else healthcheck
        ),
    }

    return [
        {
            "Id": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            "Name": f"/{name}",
            "Config": config,
            "HostConfig": host_config,
            "Mounts": list(mounts) if mounts is not None else [],
        }
    ]


def daemon_config(**overrides: Any) -> Dict[str, Any]:
    """Build a hardened ``daemon.json`` mapping, then apply the overrides."""
    config: Dict[str, Any] = {
        "hosts": ["unix:///var/run/docker.sock"],
        "tls": True,
        "tlsverify": True,
        "authorization-plugins": ["authz-broker"],
        "userns-remap": "default",
        "no-new-privileges": True,
        "userland-proxy": False,
        "live-restore": True,
        "icc": False,
        "iptables": True,
        "seccomp-profile": "/etc/docker/seccomp.json",
        "log-driver": "json-file",
        "log-opts": {"max-size": "10m", "max-file": "3"},
        "default-ulimits": {"nofile": {"Name": "nofile", "Soft": 1024, "Hard": 2048}},
    }
    config.update(overrides)
    return config


def compose_service(**overrides: Any) -> Dict[str, Any]:
    """Build a hardened Compose service, then apply the overrides."""
    service: Dict[str, Any] = {
        "image": "ghcr.io/example/api:1.4.2",
        "user": "10001:10001",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "environment": {"DB_PASSWORD": "${DB_PASSWORD}"},
        "mem_limit": "512m",
        "cpus": 1.0,
        "healthcheck": {"test": ["CMD", "true"], "interval": "30s"},
        "volumes": ["./data:/data:ro"],
    }
    service.update(overrides)
    return service
