"""Security constants shared by the scanners.

Keeping the reference data in one module guarantees that a Dockerfile check and
its Compose/container counterpart agree on what "sensitive" means (same port
list, same dangerous capabilities, same host paths).
"""

from __future__ import annotations

from typing import Iterable

#: Ports that must stay on an internal network: management interfaces,
#: datastores, caches and the Docker API itself.
SENSITIVE_PORTS = frozenset(
    {22, 23, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 7001, 8086, 9042, 9200, 9300, 11211, 27017}
)

#: Capabilities that are effectively equivalent to root on the host. The
#: capabilities Docker grants by default are deliberately absent from this set.
DANGEROUS_CAPABILITIES = frozenset(
    {
        "ALL",
        "AUDIT_CONTROL",
        "BPF",
        "DAC_READ_SEARCH",
        "LEASE",
        "MAC_ADMIN",
        "NET_ADMIN",
        "NET_BROADCAST",
        "PERFMON",
        "SYSLOG",
        "SYS_ADMIN",
        "SYS_BOOT",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "SYS_TIME",
        "WAKE_ALARM",
    }
)

#: Host paths whose mount gives access to far more than the application data.
SENSITIVE_HOST_PATHS = (
    "/",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/sys",
    "/usr",
    "/var/lib/docker",
    "/var/lib/kubelet",
    "/var/run",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/etc/kubernetes",
)

#: Paths that live under a sensitive prefix but are legitimately mounted by
#: Docker itself or by a container runtime integration.
SAFE_HOST_EXCEPTIONS = frozenset(
    {
        "/etc/hosts",
        "/etc/hostname",
        "/etc/localtime",
        "/etc/resolv.conf",
        "/etc/timezone",
        "/run/secrets",
        "/var/run/secrets",
    }
)

#: Image tags that move: a rebuild or a pull can silently change the content.
MUTABLE_IMAGE_TAGS = frozenset(
    {"latest", "main", "master", "stable", "dev", "develop", "edge", "nightly", "unstable"}
)


def is_sensitive_host_path(path: str) -> bool:
    """Return ``True`` when mounting ``path`` exposes the host.

    A path is sensitive when it is one of :data:`SENSITIVE_HOST_PATHS` or lives
    underneath one of them. The exceptions in :data:`SAFE_HOST_EXCEPTIONS` are
    checked first, because ``/etc/hosts`` is a standard, harmless bind mount.

    The root path is handled explicitly: ``/`` is the most dangerous bind mount
    there is, and normalising it away would silently disable the check.
    """
    cleaned = str(path or "").strip().strip("\"'")
    if not cleaned:
        return False
    normalized = cleaned if cleaned.startswith("/") else f"/{cleaned}"
    normalized = normalized.rstrip("/") or "/"
    if normalized in SAFE_HOST_EXCEPTIONS:
        return False
    for sensitive in SENSITIVE_HOST_PATHS:
        if normalized == sensitive:
            return True
        if sensitive != "/" and normalized.startswith(sensitive):
            return True
    return False


def is_dangerous_capability(capability: str) -> bool:
    """Return ``True`` when ``capability`` is in the dangerous set (``cap_add``)."""
    return str(capability or "").strip().upper().replace("CAP_", "") in DANGEROUS_CAPABILITIES


def mutable_image_reference(reference: str) -> bool:
    """Return ``True`` when an image reference is not pinned.

    A digest pin (``app@sha256:...``) is always considered immutable, a missing
    tag and a moving tag (``latest``, ``stable``, ...) are not.
    """
    text = str(reference or "").strip()
    if not text or "@sha256:" in text:
        return False
    last_segment = text.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return True
    tag = last_segment.rsplit(":", 1)[1].lower()
    return not tag or tag in MUTABLE_IMAGE_TAGS


def first_of(values: Iterable[str], default: str = "") -> str:
    """Return the first non-empty value, or ``default`` (small CLI helper)."""
    for value in values:
        if value:
            return value
    return default


__all__ = [
    "DANGEROUS_CAPABILITIES",
    "MUTABLE_IMAGE_TAGS",
    "SAFE_HOST_EXCEPTIONS",
    "SENSITIVE_HOST_PATHS",
    "SENSITIVE_PORTS",
    "first_of",
    "is_dangerous_capability",
    "is_sensitive_host_path",
    "mutable_image_reference",
]