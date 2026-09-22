"""Docker Compose scanner: audits ``docker-compose.yml`` services (``CP-`` rules).

Compose is the place where a deployment usually becomes insecure: a service
gains the Docker socket "just to read the logs", ``privileged: true`` appears
during a debugging session and never leaves, and a database port is published
on ``0.0.0.0`` because the developer was inside a VPN.

The scanner walks ``services`` and evaluates one check per rule. Line numbers
are recovered with a best-effort regex search on the raw text, because PyYAML
does not attach source positions to the nodes it produces.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .base import BaseScanner
from .constants import (
    SENSITIVE_PORTS,
    is_dangerous_capability,
    is_sensitive_host_path,
    mutable_image_reference,
)
from .models import Category, Location, ScanResult
from .parsers import (
    as_bool,
    as_mapping,
    as_sequence,
    as_text_list,
    find_line,
    parse_yaml_text,
    read_text,
    strip_quotes,
)
from .secrets import inspect_assignments, redact

#: Paths that expose the Docker API when bind-mounted.
DOCKER_SOCKET_PATHS = ("/var/run/docker.sock", "/run/docker.sock")

#: ``security_opt`` values that remove a mandatory access control layer.
MAC_DISABLED_VALUES = (
    "seccomp:unconfined",
    "seccomp=unconfined",
    "apparmor:unconfined",
    "apparmor=unconfined",
    "label:disable",
    "label=disable",
    "no-new-privileges:false",
    "no-new-privileges=false",
)

#: Compose keys checked for CPU/memory limits.
LIMIT_KEYS = ("mem_limit", "memswap_limit", "cpus", "cpu_quota", "cpu_period", "pids_limit")


class ComposeScanner(BaseScanner):
    """Audit every service of a Docker Compose file."""

    category = Category.COMPOSE

    def scan_file(self, path: str) -> ScanResult:
        """Read ``path`` and scan it as a Compose file."""
        return self.scan_text(read_text(path), str(path))

    def scan_text(self, text: str, source: str = "docker-compose.yml") -> ScanResult:
        """Scan Compose ``text``; ``source`` is used in the report."""
        result = self._new_result(source)
        document = parse_yaml_text(text)
        document = as_mapping(document)
        if not document:
            result.errors.append(f"{source}: no Compose document found")
            return result

        services = as_mapping(document.get("services"))
        if not services:
            result.errors.append(f"{source}: no `services` section found")
            return result

        for name, service in services.items():
            config = as_mapping(service)
            service_name = str(name)
            for check in (
                self._check_privileged,
                self._check_docker_socket,
                self._check_namespaces,
                self._check_capabilities,
                self._check_mac,
                self._check_no_new_privileges,
                self._check_volumes,
                self._check_environment,
                self._check_ports,
                self._check_limits,
                self._check_read_only,
                self._check_user,
                self._check_healthcheck,
                self._check_image,
            ):
                check(result, text, service_name, config)
        return result

    # ------------------------------------------------------- location helpers
    def _location(self, result: ScanResult, text: str, service: str, key: str = "") -> Location:
        """Best-effort location: the ``key:`` line of the service when found."""
        line = 0
        if key:
            line = find_line(text, rf"^\s*{re.escape(key)}\s*:", flags=_LINE_FLAGS)
        if not line:
            line = find_line(text, rf"^\s*{re.escape(service)}\s*:\s*$", flags=_LINE_FLAGS)
        return Location(source=result.target, line=line, path=f"services.{service}")

    # ------------------------------------------------------------------ CP-001
    def _check_privileged(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-001`` when the service runs privileged."""
        if not as_bool(config.get("privileged")):
            return
        self._emit(
            result,
            "CP-001",
            location=self._location(result, text, service, "privileged"),
            evidence=f"{service}: privileged: true",
        )

    # ------------------------------------------------------------------ CP-002
    def _check_docker_socket(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-002`` when the Docker socket is bind-mounted."""
        for source_path, _, _ in _mounts(config):
            if source_path.rstrip("/") in DOCKER_SOCKET_PATHS:
                self._emit(
                    result,
                    "CP-002",
                    location=self._location(result, text, service, "volumes"),
                    evidence=f"{service}: {source_path} mounted",
                )
                return

    # ------------------------------------------------------------------ CP-003
    def _check_namespaces(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-003``/``004``/``005`` for the host network, PID and IPC namespaces."""
        network_mode = str(config.get("network_mode") or "").strip().lower()
        if network_mode == "host":
            self._emit(
                result,
                "CP-003",
                location=self._location(result, text, service, "network_mode"),
                evidence=f"{service}: network_mode: host",
            )
        for key, rule_id in (("pid", "CP-004"), ("ipc", "CP-005")):
            if str(config.get(key) or "").strip().lower() != "host":
                continue
            self._emit(
                result,
                rule_id,
                location=self._location(result, text, service, key),
                evidence=f"{service}: {key}: host",
            )

    # ------------------------------------------------------------------ CP-006
    def _check_capabilities(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-006`` when a dangerous capability is added."""
        dangerous = [
            capability
            for capability in as_text_list(config.get("cap_add"))
            if is_dangerous_capability(capability)
        ]
        if not dangerous:
            return
        self._emit(
            result,
            "CP-006",
            location=self._location(result, text, service, "cap_add"),
            evidence=f"{service}: cap_add: {', '.join(sorted(dangerous))}",
        )

    # ------------------------------------------------------- CP-007 / CP-008
    def _check_mac(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-007`` when seccomp/AppArmor confinement is disabled."""
        disabled = [option for option in _security_options(config) if option in MAC_DISABLED_VALUES]
        if not disabled:
            return
        self._emit(
            result,
            "CP-007",
            location=self._location(result, text, service, "security_opt"),
            evidence=f"{service}: security_opt: {', '.join(disabled)}",
        )

    def _check_no_new_privileges(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-008`` when ``no-new-privileges`` is not requested."""
        options = _security_options(config)
        if any(option.startswith("no-new-privileges:true") for option in options):
            return
        if any(option.startswith("no-new-privileges:false") for option in options):
            return  # already reported by CP-007
        self._emit(
            result,
            "CP-008",
            location=self._location(result, text, service, "security_opt"),
            evidence=f"{service}: security_opt does not enable no-new-privileges",
        )

    # ------------------------------------------------------------------ CP-009
    def _check_volumes(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-009`` when a sensitive host path is mounted read-write."""
        for source_path, target, mode in _mounts(config):
            normalized = source_path.rstrip("/")
            if normalized in DOCKER_SOCKET_PATHS:
                continue  # reported by CP-002
            if "ro" in mode or not source_path.startswith("/"):
                continue
            if not is_sensitive_host_path(source_path):
                continue
            self._emit(
                result,
                "CP-009",
                location=self._location(result, text, service, "volumes"),
                message=(
                    f"Host path {source_path!r} is mounted read-write at "
                    f"{target or '/<default>'}, which is broader than the "
                    "application data."
                ),
                evidence=f"{service}: {source_path}:{target}",
            )

    # ------------------------------------------------------------------ CP-010
    def _check_environment(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-010`` when a service environment variable holds a secret."""
        assignments = _environment_assignments(config)
        secrets = inspect_assignments(assignments)
        if not secrets:
            return
        names = ", ".join(sorted({name for name, _ in secrets}))
        self._emit(
            result,
            "CP-010",
            location=self._location(result, text, service, "environment"),
            message=f"Literal credential(s) in the environment of {service}: {names}.",
            evidence=f"{service}: {secrets[0][0]}={redact(secrets[0][1])}",
        )

    # ------------------------------------------------------------------ CP-011
    def _check_ports(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-011`` when a sensitive port is published on every interface."""
        exposed: List[str] = []
        for entry in as_text_list(config.get("ports")):
            host_address, host_port, container_port = _split_port(entry)
            if host_address and host_address not in {"0.0.0.0", "::", "[::]"}:
                continue  # explicitly bound, e.g. 127.0.0.1:5432:5432
            if not host_port:
                continue
            if host_port not in SENSITIVE_PORTS and container_port not in SENSITIVE_PORTS:
                continue
            exposed.append(entry)
        if not exposed:
            return
        self._emit(
            result,
            "CP-011",
            location=self._location(result, text, service, "ports"),
            message=(
                f"Sensitive port(s) published without a host address on "
                f"{service}: {', '.join(exposed)} (listening on 0.0.0.0)."
            ),
            evidence=f"{service}: {exposed[0]}",
        )

    # ------------------------------------------------------------------ CP-012
    def _check_limits(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-012`` when the service declares no CPU or memory limit."""
        # A key that is present but null (``mem_limit:`` with no value, or an
        # empty ``cpus:``) means "not set" in Compose, so it must not count as a
        # limit.
        limits = [config.get(key) for key in LIMIT_KEYS if key in config]
        if any(value not in (None, "") for value in limits):
            return
        deploy_limits = as_mapping(as_mapping(config.get("deploy")).get("resources")).get("limits")
        if as_mapping(deploy_limits):
            return
        self._emit(
            result,
            "CP-012",
            location=self._location(result, text, service),
            evidence=f"{service}: no mem_limit/cpus/deploy.resources.limits",
        )

    # ------------------------------------------------------------------ CP-013
    def _check_read_only(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-013`` when the root filesystem of the service is writable."""
        if "read_only" in config:
            if as_bool(config.get("read_only")):
                return
            self._emit(
                result,
                "CP-013",
                location=self._location(result, text, service, "read_only"),
                message=f"{service} explicitly sets `read_only: false`.",
                evidence=f"{service}: read_only: false",
            )
            return
        self._emit(
            result,
            "CP-013",
            location=self._location(result, text, service),
            evidence=f"{service}: read_only is not set",
        )

    # ------------------------------------------------------------------ CP-014
    def _check_user(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-014`` when the service does not set an explicit user."""
        if "user" not in config:
            self._emit(
                result,
                "CP-014",
                location=self._location(result, text, service),
                evidence=f"{service}: user is not set",
            )
            return
        value = strip_quotes(str(config.get("user") or "")).strip()
        if re.fullmatch(r"(?:root|0)(?::(?:root|0))?", value, re.IGNORECASE):
            self._emit(
                result,
                "CP-014",
                location=self._location(result, text, service, "user"),
                message=f"{service} runs as root (user: {value}).",
                evidence=f"{service}: user: {value}",
            )

    # ------------------------------------------------------------------ CP-015
    def _check_healthcheck(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-015`` when the service has no healthcheck."""
        healthcheck = config.get("healthcheck")
        if healthcheck is None:
            self._emit(
                result,
                "CP-015",
                location=self._location(result, text, service),
                evidence=f"{service}: healthcheck is not defined",
            )
            return
        if as_bool(as_mapping(healthcheck).get("disable")):
            self._emit(
                result,
                "CP-015",
                location=self._location(result, text, service, "healthcheck"),
                message=f"{service} disables the healthcheck of its image.",
                evidence=f"{service}: healthcheck.disable: true",
            )

    # ------------------------------------------------------------------ CP-016
    def _check_image(
        self, result: ScanResult, text: str, service: str, config: Dict[str, Any]
    ) -> None:
        """``CP-016`` when the image reference can move under the deployment."""
        reference = str(config.get("image") or "").strip()
        if not reference:
            return  # a build-only service is reported by DF-003 from its Dockerfile
        if not mutable_image_reference(reference):
            return
        self._emit(
            result,
            "CP-016",
            location=self._location(result, text, service, "image"),
            message=(
                f"Image {reference!r} of {service} is not pinned by digest, so a "
                "pull can deploy something else than what was reviewed."
            ),
            evidence=f"{service}: image: {reference}",
        )


# --------------------------------------------------------------------- helpers
#: ``^`` must match the beginning of every line, and keys stay case-insensitive.
_LINE_FLAGS = re.IGNORECASE | re.MULTILINE


def _security_options(config: Dict[str, Any]) -> List[str]:
    """Return the normalised ``security_opt`` values of a service."""
    return [
        option.lower().replace(" ", "")
        for option in as_text_list(config.get("security_opt"))
    ]


def _mounts(config: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Return the ``(source, target, mode)`` triples of a service.

    Handles both the short syntax (``"/host:/container:ro"``, a named volume or
    an anonymous volume) and the long syntax (``type: bind`` mappings), so that
    ``CP-002`` and ``CP-009`` see every mount.
    """
    mounts: List[Tuple[str, str, str]] = []
    for entry in as_sequence(config.get("volumes")):
        if isinstance(entry, dict):
            source = str(entry.get("source") or "").strip()
            target = str(entry.get("target") or "").strip()
            mode = "ro" if as_bool(entry.get("read_only")) else ""
            mounts.append((source, target, mode))
            continue
        text = str(entry or "").strip()
        if not text:
            continue
        parts = _split_mount(text)
        source = parts[0] if len(parts) > 1 else ""
        target = parts[1] if len(parts) > 1 else parts[0]
        mode = parts[2].lower() if len(parts) > 2 else ""
        mounts.append((source.strip(), target.strip(), mode))
    return mounts


def _split_mount(text: str) -> List[str]:
    """Split a short mount syntax, keeping a Windows drive letter intact."""
    parts = text.split(":")
    if len(parts) > 1 and len(parts[0]) == 1 and parts[0].isalpha():
        parts = [f"{parts[0]}:{parts[1]}"] + parts[2:]
    return parts


def _environment_assignments(config: Dict[str, Any]) -> List[str]:
    """Return the ``KEY=value`` strings of the ``environment`` key.

    Supports the three Compose forms: a mapping, a list of ``KEY=value`` and a
    bare ``KEY`` (which inherits the value from the shell that runs Compose).
    """
    environment = config.get("environment")
    assignments: List[str] = []
    if isinstance(environment, dict):
        for key, value in environment.items():
            assignments.append(f"{key}={'' if value is None else value}")
    elif environment is not None:
        assignments.extend(as_text_list(environment))
    return assignments


def _split_port(entry: str) -> Tuple[str, int, int]:
    """Split a Compose ``ports`` entry into ``(host_address, host_port, container_port)``.

    Accepts the short syntax (``"5432:5432"``, ``"127.0.0.1:5432:5432"``,
    ``"5432"``) and the long syntax expressed as a string. Missing ports are
    returned as ``0`` so that the caller can skip the entry.
    """
    text = str(entry or "").strip().split("/", 1)[0]
    parts = [part.strip() for part in text.split(":")]
    if len(parts) == 1:
        return "", 0, _as_port(parts[0])
    if len(parts) == 2:
        return "", _as_port(parts[0]), _as_port(parts[1])
    return parts[0], _as_port(parts[1]), _as_port(parts[2])


def _as_port(value: str) -> int:
    """Return ``value`` as a port number, or ``0`` when it is not a number."""
    candidate = str(value or "").strip().strip("\"'")
    return int(candidate) if candidate.isdigit() else 0


__all__ = ["ComposeScanner"]