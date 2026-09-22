"""Docker daemon scanner: audits ``daemon.json`` (``DM-`` rules).

The daemon configuration is the highest-leverage file on a Docker host: a
single ``"hosts": ["tcp://0.0.0.0:2375"]`` exposes a root-equivalent API to the
whole network. The scanner reads the JSON document and, when available, the
flags of the running daemon (``--host``, ``--tls=false``, ...).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple
from urllib.parse import urlsplit

from .base import BaseScanner
from .models import Category, Location, ScanResult
from .parsers import as_bool, as_mapping, as_text_list, parse_json_text, read_text
from .secrets import SECRET_NAME_PATTERN, is_interpolation, is_literal_value, redact

#: TCP listen addresses of the Docker API.
TCP_HOST_PATTERN = re.compile(r"^tcp://", re.IGNORECASE)

#: Flags that disable the TLS verification of the API server.
TLS_DISABLING_FLAGS = ("--tls=false", "--tlsverify=false")

#: Log drivers that write to files on the host (they grow without rotation).
FILE_LOG_DRIVERS = ("json-file", "local")

#: JSON keys that hold credentials when they appear in a daemon configuration.
SECRET_KEY_SUFFIXES = ("password", "passwd", "secret", "token", "auth", "credential")


class DaemonScanner(BaseScanner):
    """Audit a ``daemon.json`` document (and optionally the daemon flags)."""

    category = Category.DAEMON

    #: Default target name used when the document is scanned from memory.
    DEFAULT_SOURCE = "/etc/docker/daemon.json"

    def scan_file(self, path: str) -> ScanResult:
        """Read ``path`` and scan it as a ``daemon.json``."""
        return self.scan_text(read_text(path), str(path))

    def scan_text(self, text: str, source: str = DEFAULT_SOURCE) -> ScanResult:
        """Scan ``daemon.json`` content; ``source`` is used in the report."""
        document = parse_json_text(text) if text.strip() else {}
        return self.scan_document(document, source, raw_text=text)

    def scan_document(
        self,
        document: Any,
        source: str = DEFAULT_SOURCE,
        flags: Iterable[str] = (),
        raw_text: str = "",
        known_keys: Optional[Iterable[str]] = None,
    ) -> ScanResult:
        """Scan an already parsed ``daemon.json`` mapping plus daemon ``flags``.

        ``known_keys`` lists the keys the caller was able to observe. It is used
        by :meth:`scan_info` (host mode): ``docker info`` does not expose every
        daemon option, and reporting a finding because a field is *absent from
        the output* would be a false positive. When it is ``None``, the document
        is the whole truth (file mode) and every absent key is reported.
        """
        result = self._new_result(source)
        config = _KnownConfig(as_mapping(document), known_keys)
        flag_list = [str(flag) for flag in flags]
        if not config and not flag_list:
            result.errors.append(f"{source}: empty daemon configuration")
            return result

        text = raw_text or ""
        self._check_api_exposure(result, config, flag_list, text)
        self._check_insecure_registries(result, config, text)
        self._check_no_new_privileges(result, config, text)
        self._check_userland_proxy(result, config, text)
        self._check_live_restore(result, config, text)
        self._check_icc(result, config, text)
        self._check_authorization_plugin(result, config, text)
        self._check_userns_remap(result, config, text)
        self._check_log_driver(result, config, text)
        self._check_iptables(result, config, text)
        self._check_ulimits(result, config, text)
        self._check_seccomp(result, config, text)
        self._check_secrets(result, config, text)
        return result

    # ----------------------------------------------------------------- helpers
    def _line(self, text: str, pattern: str) -> int:
        """Best-effort line number of ``pattern`` inside the raw document."""
        if not text:
            return 0
        compiled = re.compile(pattern, re.IGNORECASE)
        for number, line in enumerate(text.splitlines(), start=1):
            if compiled.search(line):
                return number
        return 0

    def _location(self, result: ScanResult, text: str, key: str = "") -> Location:
        """Location of a ``daemon.json`` key (line when known, path always)."""
        line = self._line(text, rf'"{re.escape(key)}"\s*:') if key else 0
        return Location(source=result.target, line=line, path=key)

    # ------------------------------------------------------------------ DM-001
    def _check_api_exposure(
        self,
        result: ScanResult,
        config: Dict[str, Any],
        flags: Sequence[str],
        text: str,
    ) -> None:
        """``DM-001`` when the API is reachable over TCP without TLS checks."""
        evidence: List[str] = []
        for entry in as_text_list(config.get("hosts")):
            if TCP_HOST_PATTERN.match(entry):
                evidence.append(f"hosts: {entry}")
        if "tls" in config and not as_bool(config.get("tls")):
            evidence.append(f"tls: {config.get('tls')}")
        if "tlsverify" in config and not as_bool(config.get("tlsverify")):
            evidence.append(f"tlsverify: {config.get('tlsverify')}")
        for flag in flags:
            normalized = flag.strip().strip('"').lower()
            if normalized.startswith(("--host=tcp:", "-h=tcp:")) or normalized in TLS_DISABLING_FLAGS:
                evidence.append(flag)
        if not evidence:
            return
        self._emit(
            result,
            "DM-001",
            location=self._location(result, text, "hosts"),
            message="The Docker API is reachable on a network socket: " + "; ".join(evidence) + ".",
            evidence="; ".join(evidence),
        )

    # ------------------------------------------------------------------ DM-002
    def _check_insecure_registries(
        self, result: ScanResult, config: Dict[str, Any], text: str
    ) -> None:
        """``DM-002`` when a registry is trusted over plain HTTP."""
        registries = as_text_list(config.get("insecure-registries"))
        if not registries:
            return
        self._emit(
            result,
            "DM-002",
            location=self._location(result, text, "insecure-registries"),
            evidence="insecure-registries: " + ", ".join(registries),
        )

    # ------------------------------------------------------------------ DM-003
    def _check_no_new_privileges(
        self, result: ScanResult, config: Dict[str, Any], text: str
    ) -> None:
        """``DM-003`` when the daemon does not enforce ``no-new-privileges``."""
        if _unobserved(config, "no-new-privileges") or as_bool(config.get("no-new-privileges")):
            return
        self._emit(
            result,
            "DM-003",
            location=self._location(result, text, "no-new-privileges"),
            evidence="no-new-privileges is not enabled (default false)",
        )

    # ------------------------------------------------------------------ DM-004
    def _check_userland_proxy(
        self, result: ScanResult, config: Dict[str, Any], text: str
    ) -> None:
        """``DM-004`` when the userland proxy stays enabled."""
        if _unobserved(config, "userland-proxy"):
            return
        if "userland-proxy" in config and not as_bool(config.get("userland-proxy")):
            return
        self._emit(
            result,
            "DM-004",
            location=self._location(result, text, "userland-proxy"),
            evidence="userland-proxy is not disabled (default true)",
        )

    # ------------------------------------------------------------------ DM-005
    def _check_live_restore(
        self, result: ScanResult, config: Dict[str, Any], text: str
    ) -> None:
        """``DM-005`` when ``live-restore`` is not enabled."""
        if _unobserved(config, "live-restore") or as_bool(config.get("live-restore")):
            return
        self._emit(
            result,
            "DM-005",
            location=self._location(result, text, "live-restore"),
            evidence="live-restore is not enabled (default false)",
        )

    # ------------------------------------------------------------------ DM-006
    def _check_icc(self, result: ScanResult, config: Dict[str, Any], text: str) -> None:
        """``DM-006`` when inter-container communication stays enabled."""
        if _unobserved(config, "icc"):
            return
        if "icc" in config and not as_bool(config.get("icc")):
            return
        self._emit(
            result,
            "DM-006",
            location=self._location(result, text, "icc"),
            evidence="icc is not disabled (default true)",
        )

    # ------------------------------------------------------------------ DM-007
    def _check_authorization_plugin(
        self, result: ScanResult, config: Dict[str, Any], text: str
    ) -> None:
        """``DM-007`` when no authorization plugin restricts the API."""
        if _unobserved(config, "authorization-plugins"):
            return
        if as_text_list(config.get("authorization-plugins")):
            return
        self._emit(
            result,
            "DM-007",
            location=self._location(result, text, "authorization-plugins"),
            evidence="authorization-plugins is empty",
        )

    # ------------------------------------------------------------------ DM-008
    def _check_userns_remap(self, result: ScanResult, config: Dict[str, Any], text: str) -> None:
        """``DM-008`` when user namespace remapping is not enabled."""
        if _unobserved(config, "userns-remap"):
            return
        value = config.get("userns-remap")
        if value and str(value).lower() not in {"false", "none", "0"}:
            return
        self._emit(
            result,
            "DM-008",
            location=self._location(result, text, "userns-remap"),
            evidence="userns-remap is not enabled",
        )

    # ------------------------------------------------------------------ DM-009
    def _check_log_driver(self, result: ScanResult, config: Dict[str, Any], text: str) -> None:
        """``DM-009`` when a file-based log driver has no rotation."""
        driver = str(config.get("log-driver") or "json-file").strip().lower()
        if driver and driver not in FILE_LOG_DRIVERS:
            return
        if _unobserved(config, "log-opts"):
            return
        options = as_mapping(config.get("log-opts"))
        if str(options.get("max-size") or "").strip() and str(options.get("max-file") or "").strip():
            return
        self._emit(
            result,
            "DM-009",
            location=self._location(result, text, "log-opts"),
            message=f"The {driver or 'json-file'} log driver has no max-size/max-file rotation.",
            evidence=f"log-driver: {driver or 'json-file'}, log-opts: {options or {}}",
        )

    # ------------------------------------------------------------------ DM-010
    def _check_iptables(self, result: ScanResult, config: Dict[str, Any], text: str) -> None:
        """``DM-010`` when ``iptables`` management is disabled."""
        if "iptables" not in config or as_bool(config.get("iptables")):
            return
        self._emit(
            result,
            "DM-010",
            location=self._location(result, text, "iptables"),
            evidence=f"iptables: {config.get('iptables')}",
        )

    # ------------------------------------------------------------------ DM-011
    def _check_ulimits(self, result: ScanResult, config: Dict[str, Any], text: str) -> None:
        """``DM-011`` when a default ulimit is set to unlimited."""
        ulimits = as_mapping(config.get("default-ulimits"))
        unlimited: List[str] = []
        for name, limits in ulimits.items():
            values = as_mapping(limits)
            for kind in ("Soft", "Hard"):
                value = values.get(kind)
                if value is None:
                    continue
                if str(value).strip().lower() in {"-1", "-1.0", "unlimited"}:
                    unlimited.append(f"{name}.{kind}")
        if not unlimited:
            return
        self._emit(
            result,
            "DM-011",
            location=self._location(result, text, "default-ulimits"),
            evidence="default-ulimits unlimited: " + ", ".join(sorted(unlimited)),
        )

    # ------------------------------------------------------------------ DM-012
    def _check_seccomp(self, result: ScanResult, config: Dict[str, Any], text: str) -> None:
        """``DM-012`` when the daemon disables the seccomp profile."""
        profile = str(config.get("seccomp-profile") or "").strip().lower()
        if profile not in {"unconfined", "none"}:
            return
        self._emit(
            result,
            "DM-012",
            location=self._location(result, text, "seccomp-profile"),
            evidence=f"seccomp-profile: {config.get('seccomp-profile')}",
        )

    # ------------------------------------------------------------------ DM-013
    def _check_secrets(self, result: ScanResult, config: Dict[str, Any], text: str) -> None:
        """``DM-013`` when a credential is stored in ``daemon.json``.

        ``daemon.json`` is world-readable on the host and usually versioned, so
        a registry password or a proxy password inside it is a leak. The value is
        never echoed back: only its path and its length are reported.
        """
        for path, key, value in _walk(config):
            if isinstance(value, (dict, list)):
                continue
            if not isinstance(value, str) or not value.strip():
                continue
            credentials = _url_credentials(value)
            if credentials:
                self._emit(
                    result,
                    "DM-013",
                    location=self._location(result, text, path.split(".")[-1]),
                    message=(
                        f"{path} embeds a user name and a password in a URL; the "
                        "credential is stored in clear text in daemon.json."
                    ),
                    evidence=f"{path} = {credentials}",
                )
                continue
            if not _looks_like_secret_key(key) or not is_literal_value(value):
                continue
            self._emit(
                result,
                "DM-013",
                location=self._location(result, text, path.split(".")[-1]),
                message=f"A credential-looking value is stored in daemon.json at {path}.",
                evidence=f"{path} = {redact(value)}",
            )

    # ------------------------------------------------------------- host mode
    def scan_info(self, info: Dict[str, Any], source: str = "docker info") -> ScanResult:
        """Scan the ``docker info`` fields that overlap with ``daemon.json``.

        Host mode uses this so that a daemon started from systemd flags (and not
        from ``daemon.json``) is still audited: the effective values are the ones
        that matter, not where they were declared.

        Only the fields that ``docker info`` really exposes are handed to the
        scanner, and they are declared as ``known``. A daemon option that the
        output does not mention (``userland-proxy``, ``iptables``, the TLS
        settings) is therefore not reported: absence of evidence in ``docker
        info`` is not evidence of a misconfiguration.
        """
        info_map = as_mapping(info)
        config: Dict[str, Any] = {}
        for source_key, target_key in (
            ("InsecureRegistries", "insecure-registries"),
            ("LiveRestoreEnabled", "live-restore"),
            ("LoggingDriver", "log-driver"),
            ("LoggingDriverOpts", "log-opts"),
            ("Icc", "icc"),
        ):
            if source_key in info_map:
                config[target_key] = info_map[source_key]

        plugins = as_mapping(info_map.get("Plugins"))
        if "Authorization" in plugins:
            config["authorization-plugins"] = plugins.get("Authorization")

        security_options = [option.lower() for option in as_text_list(info_map.get("SecurityOptions"))]
        if "SecurityOptions" in info_map:
            config["userns-remap"] = (
                "default" if any("userns" in option for option in security_options) else "false"
            )
            config["no-new-privileges"] = any(
                "no-new-privileges" in option for option in security_options
            )
        if "log-opts" not in config and config.get("log-driver") in FILE_LOG_DRIVERS:
            # The driver is file-based and the output does not mention the
            # rotation options: those really are unset.
            config["log-opts"] = {}
        return self.scan_document(config, source, known_keys=set(config))


# --------------------------------------------------------------------- helpers
class _KnownConfig(dict):
    """A configuration mapping that remembers which keys were observed.

    ``docker info`` exposes only part of the daemon configuration, so a rule
    that fires on a *missing* key has to know whether the key was really absent
    or simply not reported. ``known is None`` means "the document is the whole
    truth", which is the case for a ``daemon.json`` read from a file.
    """

    def __init__(self, mapping: Dict[str, Any], known: Optional[Iterable[str]] = None) -> None:
        super().__init__(mapping)
        self.known = None if known is None else frozenset(str(key) for key in known)


def _unobserved(config: Dict[str, Any], key: str) -> bool:
    """Return ``True`` when ``key`` could not be observed by the caller.

    Used by the host-mode checks: reporting a finding for a field that the input
    never mentions would be a false positive, while in file mode every absent
    key is meaningful (it means the daemon runs with its insecure default).
    """
    known = getattr(config, "known", None)
    return known is not None and key not in known
def _walk(config: Dict[str, Any], prefix: str = "") -> List[Tuple[str, str, Any]]:
    """Flatten a nested mapping into ``(path, key, value)`` triples."""
    found: List[Tuple[str, str, Any]] = []
    for key, value in config.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            found.extend(_walk(value, prefix=f"{path}."))
            continue
        found.append((path, str(key), value))
    return found


def _looks_like_secret_key(key: str) -> bool:
    """Return ``True`` for a JSON key that looks like a stored credential."""
    normalized = str(key or "").strip().lower().replace("_", "-")
    if not normalized:
        return False
    if SECRET_NAME_PATTERN.search(normalized):
        return True
    return any(normalized.endswith(suffix) for suffix in SECRET_KEY_SUFFIXES)


def _url_credentials(value: str) -> str:
    """Return a redacted userinfo fragment when a URL embeds a password.

    Docker proxy settings and mirror URLs accept the ``user:password@host``
    form, which turns a configuration file into a credential store. Only the
    user name and the placeholder are returned, never the password itself.
    """
    candidate = str(value or "").strip().strip("\"'")
    if "://" not in candidate or "@" not in candidate:
        return ""
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return ""
    if not parts.password or not parts.hostname:
        return ""
    if is_interpolation(parts.password):
        return ""
    return f"{parts.scheme}://{parts.username or '<user>'}:{redact(parts.password)}@{parts.hostname}"


__all__ = ["DaemonScanner"]
