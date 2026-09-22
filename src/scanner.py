"""Scan orchestration: detect what a target is and dispatch to the scanners.

The CLI and the tests both go through :class:`Scanner`. It owns the mapping
"file name -> scanner", the directory walk, and the aggregation of the
individual results into a single :class:`~src.models.ScanResult`, so that a new
scanner only has to be registered here to become reachable from the command
line.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from .base import BaseScanner, dedupe_findings
from .compose_scanner import ComposeScanner
from .container_scanner import ContainerScanner
from .daemon_scanner import DaemonScanner
from .dockerfile_scanner import DockerfileScanner
from .logger_config import get_logger
from .models import ScanResult, Severity
from .parsers import as_mapping, parse_json_text

#: Target kinds understood by the orchestrator (``auto`` guesses from the name).
TARGET_KINDS: Tuple[str, ...] = ("auto", "dockerfile", "compose", "daemon", "info", "container")

#: Human readable list of the concrete kinds, used by the CLI error messages.
CONCRETE_KINDS: str = "|".join(kind for kind in TARGET_KINDS if kind != "auto")

#: File names that identify a Dockerfile (compared lower-cased).
DOCKERFILE_NAMES = frozenset({"dockerfile", "containerfile"})

#: File names that identify a Compose file (compared lower-cased).
COMPOSE_NAMES = frozenset(
    {
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }
)

#: File names that identify a daemon configuration.
DAEMON_NAMES = frozenset({"daemon.json", "docker-daemon.json", "docker.json", "dockerd.json"})

#: File names that identify saved ``docker inspect`` output.
CONTAINER_NAMES = frozenset(
    {
        "docker-inspect.json",
        "inspect.json",
        "containers.json",
        "docker-ps-inspect.json",
    }
)

#: File names that identify the JSON payload of ``docker info --format '{{json .}}'``.
INFO_NAMES = frozenset({"docker-info.json", "info.json", "docker-info-out.json"})

#: Directories never worth walking in a scan.
IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "target",
        "venv",
    }
)

#: Extensions that may contain a Docker configuration.
SCANNABLE_SUFFIXES = (".json", ".yml", ".yaml", ".dockerfile")

#: Upper bound on the size of a file the scanner is willing to parse.
MAX_FILE_BYTES = 4 * 1024 * 1024


class Scanner:
    """Run the right scanner(s) over a file, a directory or a text payload."""

    def __init__(
        self,
        ignore: Iterable[str] = (),
        min_severity: Severity = Severity.INFO,
        logger_name: str = "orchestrator",
    ) -> None:
        self.ignore = tuple(str(rule_id).strip().upper() for rule_id in ignore if str(rule_id).strip())
        self.min_severity = min_severity
        self.logger = get_logger(logger_name)
        # Built once so that ``--ignore`` is validated (and fails) immediately,
        # even when the target turns out to be empty.
        self._dockerfile = DockerfileScanner(self.ignore, min_severity)
        self._compose = ComposeScanner(self.ignore, min_severity)
        self._daemon = DaemonScanner(self.ignore, min_severity)
        self._container = ContainerScanner(self.ignore, min_severity)

    # ------------------------------------------------------------------ public
    def scan(self, target: str, kind: str = "auto") -> ScanResult:
        """Scan ``target`` (a file or a directory) and return the aggregated result."""
        path = Path(target)
        if path.is_dir():
            return self.scan_directory(str(path), kind=kind)
        return self.scan_file(str(path), kind=kind)

    def scan_file(self, path: str, kind: str = "auto") -> ScanResult:
        """Scan a single file, guessing its kind from its name when needed."""
        resolved = detect_kind(path) if kind == "auto" else kind
        if resolved == "unknown":
            result = ScanResult(target=str(path))
            result.errors.append(
                f"{path}: cannot tell what this file is; pass --kind {CONCRETE_KINDS}"
            )
            return result
        source = self._read(path, resolved)
        if isinstance(source, str) and source.startswith("\x00"):
            result = ScanResult(target=str(path))
            result.errors.append(source[1:])
            return result
        return self._dispatch(resolved, source, str(path))

    def scan_text(self, text: str, kind: str, source_name: str = "<stdin>") -> ScanResult:
        """Scan in-memory ``text`` of kind ``kind`` (used by ``--stdin`` and tests)."""
        if kind not in TARGET_KINDS or kind == "auto":
            result = ScanResult(target=source_name)
            result.errors.append(f"{source_name}: a concrete kind is required for in-memory content")
            return result
        return self._dispatch(kind, text, source_name)

    def scan_stdin_text(self, text: str, kind: str = "auto", source_name: str = "<stdin>") -> ScanResult:
        """Scan piped content, detecting the kind from the text when ``auto``."""
        resolved = kind if kind != "auto" else detect_kind("", text)
        if resolved == "unknown":
            result = ScanResult(target=source_name)
            result.errors.append(
                f"{source_name}: cannot detect the content kind; pass --kind dockerfile|compose|daemon|container"
            )
            return result
        return self.scan_text(text, resolved, source_name=source_name)

    def scan_directory(self, path: str, kind: str = "auto") -> ScanResult:
        """Walk ``path`` and scan every recognisable Docker configuration file."""
        result = ScanResult(target=str(path))
        files = self.find_targets(path, kind=kind)
        if not files:
            result.errors.append(f"{path}: no Docker configuration file found")
            return result
        for candidate in files:
            file_result = self.scan_file(candidate, kind=kind)
            result.extend(file_result.findings)
            for source in file_result.sources:
                result.add_source(source)
            result.errors.extend(file_result.errors)
        dedupe_findings(result)
        return result

    def find_targets(self, path: str, kind: str = "auto") -> List[str]:
        """Return the scannable files under ``path`` (sorted, ignored dirs skipped)."""
        root = Path(path)
        if root.is_file():
            return [str(root)]
        found: List[str] = []
        for candidate in sorted(root.rglob("*")):
            if not candidate.is_file():
                continue
            if any(part in IGNORED_DIRECTORIES for part in candidate.parts):
                continue
            try:
                if candidate.stat().st_size > MAX_FILE_BYTES:
                    self.logger.warning("skipping %s: file is too large", candidate)
                    continue
            except OSError:
                continue
            resolved = detect_kind(str(candidate)) if kind == "auto" else kind
            if resolved == "unknown":
                continue
            found.append(str(candidate))
        return found

    # ----------------------------------------------------------------- internal
    def _dispatch(self, kind: str, text: str, source_name: str) -> ScanResult:
        """Route already-read content to the scanner registered for ``kind``.

        ``info`` is handled here rather than in :meth:`_scanner_for`, because the
        output of ``docker info`` is not a configuration file for a scanner of
        its own: :class:`~src.daemon_scanner.DaemonScanner` reads it through
        :meth:`~src.daemon_scanner.DaemonScanner.scan_info`.
        """
        if kind == "info":
            try:
                document = parse_json_text(text) if text.strip() else {}
            except ValueError as exc:  # malformed JSON
                result = ScanResult(target=source_name)
                result.errors.append(f"{source_name}: {exc}")
                return result
            return self._daemon.scan_info(as_mapping(document), source_name)
        scanner = self._scanner_for(kind)
        try:
            return scanner.scan_text(text, source_name)
        except ValueError as exc:  # malformed JSON/YAML
            result = ScanResult(target=source_name)
            result.errors.append(f"{source_name}: {exc}")
            return result

    def _scanner_for(self, kind: str) -> BaseScanner:
        """Return the scanner instance registered for ``kind``."""
        scanners = {
            "dockerfile": self._dockerfile,
            "compose": self._compose,
            "daemon": self._daemon,
            "container": self._container,
        }
        if kind not in scanners:
            raise ValueError(f"unsupported kind {kind!r}")
        return scanners[kind]

    def _read(self, path: str, kind: str) -> str:
        """Read ``path`` as text, reporting an error as a ``"\\x00"`` prefixed string."""
        candidate = Path(path)
        if not candidate.is_file():
            return f"\x00{path}: not a file"
        try:
            if candidate.stat().st_size > MAX_FILE_BYTES:
                return f"\x00{path}: file is larger than {MAX_FILE_BYTES} bytes"
            return candidate.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"\x00{path}: {exc}"


# ---------------------------------------------------------------- detection
def detect_kind(path: str, text: Optional[str] = None) -> str:
    """Guess the target kind from the file name, then from the content.

    ``"unknown"`` is returned when nothing matches, which makes the CLI ask for
    an explicit ``--kind`` instead of silently scanning nothing.
    """
    name = Path(path).name.lower() if path else ""
    if name in DOCKERFILE_NAMES or name.startswith(("dockerfile", "containerfile")) or name.endswith(
        ".dockerfile"
    ):
        return "dockerfile"
    if name in COMPOSE_NAMES or name.startswith(("docker-compose", "compose")):
        return "compose"
    if name in DAEMON_NAMES or name.startswith(("daemon", "dockerd")):
        return "daemon"
    if name in CONTAINER_NAMES or name.startswith(("docker-inspect", "docker-ps-inspect", "inspect")):
        return "container"
    if name in INFO_NAMES or name.startswith("docker-info"):
        return "info"
    if name.endswith((".yml", ".yaml")):
        return "compose"
    if text:
        return _detect_kind_from_text(text)
    return "unknown"


def _detect_kind_from_text(text: str) -> str:
    """Guess the kind from the first meaningful lines of a document."""
    for raw_line in str(text or "").splitlines()[:40]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith(("FROM ", "ARG ", "RUN ", "CMD ", "ENTRYPOINT ", "COPY ", "ADD ")):
            return "dockerfile"
        if line.startswith(("{", "[")):
            return "unknown"
        if line.startswith(("version:", "services:", "volumes:", "networks:", "x-")):
            return "compose"
        break
    return "unknown"


__all__ = [
    "COMPOSE_NAMES",
    "CONCRETE_KINDS",
    "CONTAINER_NAMES",
    "DAEMON_NAMES",
    "DOCKERFILE_NAMES",
    "IGNORED_DIRECTORIES",
    "INFO_NAMES",
    "Scanner",
    "TARGET_KINDS",
    "detect_kind",
]