"""Container scanner: audits ``docker inspect`` output (``CT-`` rules).

This is the "runtime" half of the tool: a Dockerfile can be clean and the
container that actually runs can still be privileged, share the host network
namespace or hold a hardcoded password in ``Config.Env``. The scanner consumes
the JSON produced by ``docker inspect <container>`` (a single object, or a list
like the one returned by ``docker inspect $(docker ps -q)``) and never talks to
a daemon, so it also runs on a saved artifact in CI.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

from .base import BaseScanner
from .constants import (
    is_dangerous_capability,
    is_sensitive_host_path,
    mutable_image_reference,
)
from .models import Category, Location, ScanResult
from .parsers import as_bool, as_mapping, as_sequence, as_text_list, parse_json_text, read_text
from .secrets import inspect_assignments, redact

#: Paths that expose the Docker API when bind-mounted.
DOCKER_SOCKET_PATHS = ("/var/run/docker.sock", "/run/docker.sock")

#: ``security_opt`` values that remove the syscall filter.
SECCOMP_UNCONFINED = ("seccomp=unconfined", "seccomp:unconfined")

#: ``security_opt`` values that remove the mandatory access control policy.
MAC_UNCONFINED = (
    "apparmor=unconfined",
    "apparmor:unconfined",
    "label=disable",
    "label:disable",
    "selinux=unconfined",
    "selinux:unconfined",
)

#: ``security_opt`` entries that confine the container (AppArmor/SELinux).
MAC_CONFINED_PREFIXES = ("apparmor=", "apparmor:", "label=", "label:", "selinux=", "selinux:")


class ContainerScanner(BaseScanner):
    """Audit one or more container objects coming from ``docker inspect``."""

    category = Category.CONTAINER

    def scan_file(self, path: str) -> ScanResult:
        """Read ``path`` and scan it as ``docker inspect`` output."""
        return self.scan_text(read_text(path), str(path))

    def scan_text(self, text: str, source: str = "docker-inspect.json") -> ScanResult:
        """Scan ``docker inspect`` JSON; ``source`` is used in the report."""
        document = parse_json_text(text) if text.strip() else []
        return self.scan_document(document, source)

    def scan_document(self, document: Any, source: str = "docker-inspect.json") -> ScanResult:
        """Scan an already parsed ``docker inspect`` document.

        A document is either one container object (the output of
        ``docker inspect <container>``) or a list of them (the output of
        ``docker inspect $(docker ps -q)``). Anything that does not look like a
        container is reported instead of being scanned with every field
        missing, which would produce a report full of false positives.
        """
        containers = [
            item for item in as_sequence(document) if _looks_like_container(item)
        ]
        result = self._new_result(source)
        if not containers:
            result.errors.append(f"{source}: no container object found in the document")
            return result
        for container in containers:
            self._check_container(result, container)
        return result

    # ------------------------------------------------------------- per container
    def _check_container(self, result: ScanResult, container: Dict[str, Any]) -> None:
        """Evaluate every ``CT-`` rule against one container object."""
        name = _container_name(container)
        config = as_mapping(container.get("Config"))
        host = as_mapping(container.get("HostConfig"))
        mounts = _mounts(container, host)
        location = Location(source=result.target, path=name)

        self._check_privileged(result, host, location, name)
        self._check_docker_socket(result, mounts, location, name)
        self._check_namespaces(result, host, location, name)
        self._check_user(result, config, location, name)
        self._check_readonly(result, host, location, name)
        self._check_capabilities(result, host, location, name)
        self._check_security_opt(result, host, location, name)
        self._check_healthcheck(result, config, location, name)
        self._check_image(result, config, location, name)
        self._check_environment(result, config, location, name)
        self._check_limits(result, host, location, name)
        self._check_mounts(result, mounts, location, name)
        self._check_devices(result, host, location, name)

    # ------------------------------------------------------------------ CT-001
    def _check_privileged(
        self, result: ScanResult, host: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-001`` when ``HostConfig.Privileged`` is true."""
        if not as_bool(host.get("Privileged")):
            return
        self._emit(
            result,
            "CT-001",
            location=location,
            message=f"Container {name} runs with HostConfig.Privileged = true.",
            evidence=f"{name}: Privileged=true",
        )

    # ------------------------------------------------------------------ CT-002
    def _check_docker_socket(
        self,
        result: ScanResult,
        mounts: Sequence[Tuple[str, str, str]],
        location: Location,
        name: str,
    ) -> None:
        """``CT-002`` when the Docker socket is mounted into the container."""
        for source_path, _, _ in mounts:
            if source_path.rstrip("/") in DOCKER_SOCKET_PATHS:
                self._emit(
                    result,
                    "CT-002",
                    location=location,
                    message=f"Container {name} has the Docker socket mounted.",
                    evidence=f"{name}: {source_path}",
                )
                return

    # --------------------------------------------------- CT-003 / 004 / 005
    def _check_namespaces(
        self, result: ScanResult, host: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-003``/``004``/``005`` for the host network, PID and IPC modes."""
        if str(host.get("NetworkMode") or "").strip().lower() == "host":
            self._emit(
                result,
                "CT-003",
                location=location,
                message=f"Container {name} uses the host network namespace.",
                evidence=f"{name}: NetworkMode=host",
            )
        for key, rule_id in (("PidMode", "CT-004"), ("IpcMode", "CT-005")):
            if str(host.get(key) or "").strip().lower() != "host":
                continue
            self._emit(
                result,
                rule_id,
                location=location,
                evidence=f"{name}: {key}=host",
            )

    # ------------------------------------------------------------------ CT-006
    def _check_user(
        self, result: ScanResult, config: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-006`` when the main process runs as root."""
        user = str(config.get("User") or "").strip()
        if user and user.lower() not in {"root", "0", "0:0", "root:root", "0:root", "root:0"}:
            return
        self._emit(
            result,
            "CT-006",
            location=location,
            message=f"Container {name} runs as root (Config.User = {user or '<empty>'}).",
            evidence=f"{name}: User={user or '<empty>'}",
        )

    # ------------------------------------------------------------------ CT-007
    def _check_readonly(
        self, result: ScanResult, host: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-007`` when the root filesystem is writable."""
        if as_bool(host.get("ReadonlyRootfs")):
            return
        self._emit(
            result,
            "CT-007",
            location=location,
            evidence=f"{name}: ReadonlyRootfs=false",
        )

    # ------------------------------------------------------------------ CT-008
    def _check_capabilities(
        self, result: ScanResult, host: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-008`` when a dangerous capability was added."""
        added = [
            capability
            for capability in as_text_list(host.get("CapAdd"))
            if is_dangerous_capability(capability)
        ]
        if not added:
            return
        self._emit(
            result,
            "CT-008",
            location=location,
            message=f"Container {name} adds dangerous capabilities: {', '.join(added)}.",
            evidence=f"{name}: CapAdd={', '.join(added)}",
        )

    # --------------------------------------------------- CT-009 / CT-010 / CT-015
    def _check_security_opt(
        self, result: ScanResult, host: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-009``/``010``/``015`` for ``HostConfig.SecurityOpt``."""
        options = [option.lower().replace(" ", "") for option in as_text_list(host.get("SecurityOpt"))]

        if not any(option.startswith("no-new-privileges") for option in options):
            self._emit(
                result,
                "CT-009",
                location=location,
                evidence=f"{name}: no-new-privileges is missing from SecurityOpt",
            )
        if any(option in SECCOMP_UNCONFINED for option in options):
            self._emit(
                result,
                "CT-010",
                location=location,
                evidence=f"{name}: SecurityOpt={', '.join(options)}",
            )
        if any(option in MAC_UNCONFINED for option in options):
            self._emit(
                result,
                "CT-015",
                location=location,
                message=f"Container {name} disables its mandatory access control policy.",
                evidence=f"{name}: SecurityOpt={', '.join(options)}",
            )
        elif not any(option.startswith(MAC_CONFINED_PREFIXES) for option in options):
            self._emit(
                result,
                "CT-015",
                location=location,
                evidence=f"{name}: no AppArmor/SELinux confinement in SecurityOpt",
            )

    # ------------------------------------------------------------------ CT-011
    def _check_healthcheck(
        self, result: ScanResult, config: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-011`` when the container has no active healthcheck."""
        healthcheck = config.get("Healthcheck")
        if isinstance(healthcheck, dict) and healthcheck:
            test = as_text_list(healthcheck.get("Test"))
            if not (test and str(test[0]).upper() == "NONE"):
                return
            message = f"Container {name} disables the healthcheck of its image."
        else:
            message = f"Container {name} has no healthcheck."
        self._emit(result, "CT-011", location=location, message=message)

    # ------------------------------------------------------------------ CT-012
    def _check_image(
        self, result: ScanResult, config: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-012`` when the image reference can move under the container."""
        reference = str(config.get("Image") or "").strip()
        if not reference or not mutable_image_reference(reference):
            return
        self._emit(
            result,
            "CT-012",
            location=location,
            message=f"Container {name} runs image {reference!r}, which is not pinned by digest.",
            evidence=f"{name}: Image={reference}",
        )

    # ------------------------------------------------------------------ CT-013
    def _check_environment(
        self, result: ScanResult, config: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-013`` when ``Config.Env`` holds a literal credential."""
        secrets = inspect_assignments(as_text_list(config.get("Env")))
        if not secrets:
            return
        names = ", ".join(sorted({key for key, _ in secrets}))
        self._emit(
            result,
            "CT-013",
            location=location,
            message=f"Literal credential(s) in the environment of {name}: {names}.",
            evidence=f"{name}: {secrets[0][0]}={redact(secrets[0][1])}",
        )

    # ------------------------------------------------------------------ CT-014
    def _check_limits(
        self, result: ScanResult, host: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-014`` when no CPU or memory limit is configured."""
        if (
            _as_number(host.get("Memory"))
            or _as_number(host.get("NanoCpus"))
            or _as_number(host.get("CpuShares"))
        ):
            return
        self._emit(
            result,
            "CT-014",
            location=location,
            evidence=f"{name}: Memory=0, NanoCpus=0",
        )

    # ------------------------------------------------------------------ CT-016
    def _check_mounts(
        self,
        result: ScanResult,
        mounts: Sequence[Tuple[str, str, str]],
        location: Location,
        name: str,
    ) -> None:
        """``CT-016`` when a sensitive host path is mounted read-write."""
        for source_path, target, mode in mounts:
            if "ro" in mode.lower() or not source_path.startswith("/"):
                continue
            if source_path.rstrip("/") in DOCKER_SOCKET_PATHS:
                continue  # reported by CT-002, which explains the impact better
            if not is_sensitive_host_path(source_path):
                continue
            self._emit(
                result,
                "CT-016",
                location=location,
                message=(
                    f"Container {name} mounts the host path {source_path!r} "
                    f"read-write at {target or '/<default>'}."
                ),
                evidence=f"{name}: {source_path}:{target}",
            )

    # ------------------------------------------------------------------ CT-017
    def _check_devices(
        self, result: ScanResult, host: Dict[str, Any], location: Location, name: str
    ) -> None:
        """``CT-017`` when a host device is exposed to the container."""
        paths = [
            str(entry.get("PathOnHost") or "").strip()
            for entry in as_sequence(host.get("Devices"))
            if isinstance(entry, dict) and str(entry.get("PathOnHost") or "").strip()
        ]
        if not paths:
            return
        self._emit(
            result,
            "CT-017",
            location=location,
            message=f"Container {name} has access to host device(s): {', '.join(paths)}.",
            evidence=f"{name}: Devices: {', '.join(paths)}",
        )


# --------------------------------------------------------------------- helpers
#: Keys that identify a ``docker inspect`` container object.
CONTAINER_MARKERS = (
    "Config",
    "HostConfig",
    "Id",
    "Image",
    "Mounts",
    "Name",
    "NetworkSettings",
    "State",
)


def _looks_like_container(document: Any) -> bool:
    """Return ``True`` when ``document`` is a ``docker inspect`` container object.

    The check keeps the scanner useful when the wrong file is passed: a
    ``daemon.json`` or a Compose document would otherwise be scanned as a
    container with every field missing, which produces a report full of
    findings that do not correspond to anything real.
    """
    if not isinstance(document, dict):
        return False
    return any(key in document for key in CONTAINER_MARKERS)


def _container_name(container: Dict[str, Any]) -> str:
    """Return the display name of a ``docker inspect`` object."""
    name = str(container.get("Name") or "").strip().lstrip("/")
    if name:
        return name
    identifier = str(container.get("Id") or "").strip()
    return identifier[:12] if identifier else "<unnamed>"


def _mounts(container: Dict[str, Any], host: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Return the unique ``(source, target, mode)`` triples of a container.

    ``docker inspect`` reports mounts twice: the normalised list in ``Mounts``
    (binds and volumes) and the raw ``HostConfig.Binds`` list. Both are read so
    that a mount is never missed because of a Docker version difference, and the
    result is de-duplicated so that a single mount is reported once.
    """
    mounts: List[Tuple[str, str, str]] = []
    for entry in as_sequence(container.get("Mounts")):
        if not isinstance(entry, dict):
            continue
        source = str(entry.get("Source") or "").strip()
        target = str(entry.get("Destination") or "").strip()
        if not source and not target:
            continue
        mode = "" if as_bool(entry.get("RW", True)) else "ro"
        mounts.append((source, target, mode))

    for entry in as_text_list(host.get("Binds")):
        parts = _split_mount(entry)
        source = parts[0].strip()
        target = parts[1].strip() if len(parts) > 1 else ""
        mode = parts[2].strip().lower() if len(parts) > 2 else ""
        mounts.append((source, target, mode))
    return _unique(mounts)


def _unique(mounts: Sequence[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    """Drop duplicate mount triples while keeping their original order."""
    seen = set()
    unique: List[Tuple[str, str, str]] = []
    for mount in mounts:
        if mount in seen:
            continue
        seen.add(mount)
        unique.append(mount)
    return unique


def _split_mount(text: str) -> List[str]:
    """Split a ``HostConfig.Binds`` entry, keeping a Windows drive letter intact."""
    parts = str(text or "").split(":")
    if len(parts) > 1 and len(parts[0]) == 1 and parts[0].isalpha():
        parts = [f"{parts[0]}:{parts[1]}"] + parts[2:]
    return parts


def _as_number(value: Any) -> float:
    """Return ``value`` as a number, or ``0.0`` when it is not numeric."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


__all__ = ["ContainerScanner"]