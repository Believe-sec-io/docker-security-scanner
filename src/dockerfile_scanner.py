"""Dockerfile scanner: audits build instructions against the ``DF-`` rules.

The scanner never executes anything: it reads the text, splits it into
instructions (see :mod:`src.parsers`) and evaluates one check per rule. Every
check is a small private method so that a rule can be traced to the code that
implements it, and so that a test can exercise one rule in isolation.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

from .base import BaseScanner
from .constants import SENSITIVE_PORTS
from .models import Category, Location, ScanResult
from .parsers import (
    Instruction,
    instructions_of,
    parse_dockerfile,
    read_text,
    strip_quotes,
    unquote_command,
)
from .secrets import first_secret_in_text, inspect_assignments, redact, split_assignment

#: Packages that should never be installed in a container image.
SSH_PACKAGES = ("openssh-server", "openssh-client", "openssh", "dropbear", "sshd")

#: File names that carry credentials when copied into an image layer.
SENSITIVE_COPY_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pgpass",
        ".dockercfg",
        ".git-credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials",
        "credentials.json",
        "kubeconfig",
        "secrets.yml",
        "secrets.yaml",
        ".htpasswd",
    }
)

#: Extensions of credential material.
SENSITIVE_COPY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk")

#: Directories whose content is credential material.
SENSITIVE_COPY_SEGMENTS = (".git", ".ssh", ".aws", ".gnupg", ".kube", ".docker", "secrets")

#: ``curl https://... | sh`` and friends.
REMOTE_SCRIPT = re.compile(
    r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b"
    r"|\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node)\b",
    re.IGNORECASE,
)

#: World-writable permissions granted with ``chmod``.
WORLD_WRITABLE = re.compile(
    r"\bchmod\b[^;&|]*?(?:[0-7]?[2367][2367][2367]|(?:a|o|ugo)\+w)\b",
    re.IGNORECASE,
)

#: Cache cleanups that make a package installation acceptable.
APT_CACHE_CLEAN = re.compile(r"rm\s+-rf?\s+/var/lib/apt/lists", re.IGNORECASE)
APK_CACHE_CLEAN = re.compile(r"rm\s+-rf?\s+/var/cache/apk", re.IGNORECASE)
YUM_CACHE_CLEAN = re.compile(
    r"rm\s+-rf?\s+/var/cache/(?:yum|dnf)|\b(?:yum|dnf|microdnf)\s+clean\s+all",
    re.IGNORECASE,
)

#: Direct ``sudo`` invocation inside a RUN instruction.
SUDO_USE = re.compile(r"(?:^|[;&|]\s*|\s)sudo\s+\S", re.IGNORECASE)

#: Package managers whose install commands are checked for version pins.
INSTALL_PATTERNS = (
    re.compile(r"\b(?:apt-get|apt)\s+install\s+(?P<packages>[^&;|\n]*)", re.IGNORECASE),
    re.compile(r"\bapk\s+add\s+(?P<packages>[^&;|\n]*)", re.IGNORECASE),
    re.compile(r"\b(?:pip|pip3|python3?\s+-m\s+pip)\s+install\s+(?P<packages>[^&;|\n]*)", re.IGNORECASE),
    re.compile(r"\b(?:yum|dnf|microdnf)\s+install\s+(?P<packages>[^&;|\n]*)", re.IGNORECASE),
)

#: Version pin separators understood by the supported package managers.
PIN_SEPARATORS = ("==", "=", "@")


class DockerfileScanner(BaseScanner):
    """Audit a Dockerfile and report every insecure build instruction."""

    category = Category.DOCKERFILE

    def scan_file(self, path: str) -> ScanResult:
        """Read ``path`` and scan it as a Dockerfile."""
        return self.scan_text(read_text(path), str(path))

    def scan_text(self, text: str, source: str = "Dockerfile") -> ScanResult:
        """Scan Dockerfile ``text``; ``source`` is used in the report."""
        result = self._new_result(source)
        instructions = parse_dockerfile(text)
        if not instructions:
            result.errors.append(f"{source}: no Dockerfile instruction found")
            return result

        self._check_user(result, instructions)
        self._check_base_image(result, instructions)
        self._check_add(result, instructions)
        self._check_run_commands(result, instructions)
        self._check_secrets(result, instructions)
        self._check_exposed_ports(result, instructions)
        self._check_healthcheck(result, instructions)
        self._check_copies(result, instructions)
        self._check_commands(result, instructions)
        return result

    # ------------------------------------------------------- DF-001 / DF-002
    def _check_user(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-001`` when no USER is set, ``DF-002`` when it is root."""
        users = instructions_of(instructions, "USER")
        if not users:
            stages = instructions_of(instructions, "FROM")
            if not stages:
                return
            self._emit(
                result,
                "DF-001",
                location=Location(source=result.target, line=stages[0][0]),
                message="No USER instruction is present anywhere in the Dockerfile.",
            )
            return
        for line, _, argument in users:
            value = strip_quotes(argument).strip()
            if re.fullmatch(r"(?:root|0)(?::(?:root|0))?", value, re.IGNORECASE):
                self._emit(
                    result,
                    "DF-002",
                    location=Location(source=result.target, line=line),
                    evidence=f"USER {value}",
                )

    # ------------------------------------------------------------------ DF-003
    def _check_base_image(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-003`` when a FROM reference is not pinned to a digest."""
        for line, _, argument in instructions_of(instructions, "FROM"):
            reference = _from_reference(argument)
            if reference is None or _is_pinned(reference):
                continue
            self._emit(
                result,
                "DF-003",
                location=Location(source=result.target, line=line),
                message=f"Base image {reference!r} is not pinned by digest.",
                evidence=f"FROM {reference}",
            )

    # ------------------------------------------------------------------ DF-004
    def _check_add(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-004`` when ADD downloads a remote resource."""
        for line, _, argument in instructions_of(instructions, "ADD"):
            for token in _arguments(argument):
                if not re.match(r"(?:https?|ftp|git)://|^git@", token, re.IGNORECASE):
                    continue
                self._emit(
                    result,
                    "DF-004",
                    location=Location(source=result.target, line=line),
                    evidence=f"ADD {token}",
                )
                break

    # ------------------------------------- DF-005 / 007 / 008 / 009 / 012 / 014
    def _check_run_commands(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """Inspect every RUN instruction for the command-line based rules."""
        for line, _, command in instructions_of(instructions, "RUN"):
            location = Location(source=result.target, line=line)
            if REMOTE_SCRIPT.search(command):
                self._emit(result, "DF-005", location=location, evidence=_snippet(command))
            if WORLD_WRITABLE.search(command):
                self._emit(
                    result,
                    "DF-007",
                    location=location,
                    evidence=_matching_fragment(WORLD_WRITABLE, command),
                )
            self._check_cache_cleanup(result, command, location)
            self._check_sudo(result, command, location)
            self._check_ssh_server(result, command, location)
            self._check_unpinned_packages(result, command, location)

    # ------------------------------------------------------------------ DF-008
    def _check_cache_cleanup(self, result: ScanResult, command: str, location: Location) -> None:
        """``DF-008`` when a package manager leaves its index in the layer."""
        managers: List[str] = []
        if re.search(r"\b(?:apt-get|apt)\s+(?:install|update|upgrade)\b", command, re.IGNORECASE):
            if not APT_CACHE_CLEAN.search(command):
                managers.append("apt")
        if re.search(r"\bapk\s+(?:add|upgrade|update)\b", command, re.IGNORECASE):
            if "--no-cache" not in command and not APK_CACHE_CLEAN.search(command):
                managers.append("apk")
        if re.search(r"\b(?:yum|dnf|microdnf)\s+(?:install|upgrade)\b", command, re.IGNORECASE):
            if not YUM_CACHE_CLEAN.search(command):
                managers.append("yum")
        if managers:
            self._emit(
                result,
                "DF-008",
                location=location,
                message=f"The {'/'.join(managers)} package index is kept in the image layer.",
                evidence=_snippet(command),
            )

    # ------------------------------------------------------------------ DF-009
    def _check_sudo(self, result: ScanResult, command: str, location: Location) -> None:
        """``DF-009`` when sudo is installed or invoked."""
        evidence = ""
        if SUDO_USE.search(command):
            evidence = "sudo invoked in RUN"
        else:
            for token in _installed_packages(command):
                if token.split("=", 1)[0].lower().startswith("sudo"):
                    evidence = f"sudo installed: {token}"
                    break
        if evidence:
            self._emit(result, "DF-009", location=location, evidence=evidence)

    # ------------------------------------------------------------------ DF-012
    def _check_ssh_server(self, result: ScanResult, command: str, location: Location) -> None:
        """``DF-012`` when an SSH daemon is installed in the image."""
        for token in _installed_packages(command):
            name = token.split("=", 1)[0].split("@", 1)[0].lower()
            if name in SSH_PACKAGES:
                self._emit(
                    result,
                    "DF-012",
                    location=location,
                    evidence=f"SSH server installed: {token}",
                )
                return

    # ------------------------------------------------------------------ DF-014
    def _check_unpinned_packages(self, result: ScanResult, command: str, location: Location) -> None:
        """``DF-014`` when packages are installed without a version pin."""
        unpinned: List[str] = []
        for pattern in INSTALL_PATTERNS:
            for match in pattern.finditer(command):
                packages = match.group("packages")
                if re.search(r"(?<!\S)-r\s", packages):
                    continue  # ``pip install -r requirements.txt``
                for token in _package_tokens(packages):
                    if any(separator in token for separator in PIN_SEPARATORS):
                        continue
                    unpinned.append(token)
        if unpinned:
            summary = ", ".join(sorted(set(unpinned))[:5])
            self._emit(
                result,
                "DF-014",
                location=location,
                message="Packages are installed without pinning a version.",
                evidence=f"unpinned: {summary}",
            )

    # ------------------------------------------------------------------ DF-006
    def _check_secrets(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-006`` when ENV/ARG/LABEL (or RUN) hardcodes a credential."""
        for name in ("ENV", "ARG", "LABEL"):
            for line, _, argument in instructions_of(instructions, name):
                pairs = _assignments(argument, legacy_pairs=name == "ENV")
                for key, value in inspect_assignments(f"{key}={value}" for key, value in pairs):
                    self._emit(
                        result,
                        "DF-006",
                        location=Location(source=result.target, line=line),
                        message=f"{name} {key} holds a hardcoded credential.",
                        evidence=f"{name} {key}={redact(value)}",
                    )
        for line, _, command in instructions_of(instructions, "RUN"):
            found = first_secret_in_text(command)
            if found is None:
                continue
            key, value = found
            self._emit(
                result,
                "DF-006",
                location=Location(source=result.target, line=line),
                message=f"RUN assigns a hardcoded credential to {key}.",
                evidence=f"RUN {key}={redact(value)}",
            )

    # ------------------------------------------------------------------ DF-010
    def _check_exposed_ports(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-010`` when a management or datastore port is exposed."""
        for line, _, argument in instructions_of(instructions, "EXPOSE"):
            for token in _arguments(argument):
                if any(port in SENSITIVE_PORTS for port in _ports_of(token)):
                    self._emit(
                        result,
                        "DF-010",
                        location=Location(source=result.target, line=line),
                        evidence=f"EXPOSE {token}",
                    )
                    break

    # ------------------------------------------------------------------ DF-011
    def _check_healthcheck(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-011`` when no active HEALTHCHECK is declared."""
        stages = instructions_of(instructions, "FROM")
        if not stages:
            return
        healthchecks = instructions_of(instructions, "HEALTHCHECK")
        if healthchecks and not _is_disabled_healthcheck(healthchecks[-1][2]):
            return
        message = (
            "HEALTHCHECK is explicitly disabled with NONE."
            if healthchecks
            else "No HEALTHCHECK instruction is present in the Dockerfile."
        )
        self._emit(
            result,
            "DF-011",
            location=Location(source=result.target, line=stages[0][0]),
            message=message,
        )

    # ------------------------------------------------------------------ DF-013
    def _check_copies(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-013`` when credential material is copied into a layer."""
        for name in ("COPY", "ADD"):
            for line, _, argument in instructions_of(instructions, name):
                sources = _arguments(argument)[:-1]  # the last token is the target
                for source in sources:
                    reason = _sensitive_copy_reason(source)
                    if not reason:
                        continue
                    self._emit(
                        result,
                        "DF-013",
                        location=Location(source=result.target, line=line),
                        message=f"{name} copies credential material into the image ({reason}).",
                        evidence=f"{name} {source}",
                    )

    # ------------------------------------------------------------------ DF-015
    def _check_commands(self, result: ScanResult, instructions: Sequence[Instruction]) -> None:
        """``DF-015`` when CMD/ENTRYPOINT uses the shell form."""
        for name in ("CMD", "ENTRYPOINT"):
            for line, _, argument in instructions_of(instructions, name):
                if unquote_command(argument) is not None:
                    continue
                self._emit(
                    result,
                    "DF-015",
                    location=Location(source=result.target, line=line),
                    evidence=f"{name} {_snippet(argument)}",
                )


# --------------------------------------------------------------------- helpers
def _arguments(argument: str) -> List[str]:
    """Split an instruction argument into tokens, dropping option flags."""
    return [token for token in str(argument or "").split() if not token.startswith("-")]


def _snippet(text: str, limit: int = 120) -> str:
    """Collapse whitespace and truncate ``text`` so reports stay readable."""
    collapsed = " ".join(str(text or "").split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."


def _matching_fragment(pattern: re.Pattern, text: str, limit: int = 120) -> str:
    """Return the part of ``text`` matched by ``pattern`` (or the whole text)."""
    match = pattern.search(text)
    return _snippet(match.group(0), limit) if match else _snippet(text, limit)


def _from_reference(argument: str) -> Optional[str]:
    """Return the image reference of a FROM instruction.

    ``None`` means "cannot be decided": ``scratch`` has no registry to pin, and
    a reference containing ``$`` is resolved from a build argument.
    """
    tokens = _arguments(argument)
    if not tokens:
        return None
    reference = tokens[0]
    if reference.lower() == "scratch" or "$" in reference:
        return None
    return reference


def _is_pinned(reference: str) -> bool:
    """Return ``True`` when the image reference is pinned by digest or tag."""
    if "@sha256:" in reference:
        return True
    last_segment = reference.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return False
    tag = last_segment.rsplit(":", 1)[1]
    return bool(tag) and tag.lower() != "latest"


def _ports_of(token: str) -> List[int]:
    """Expand an EXPOSE token (``80``, ``80/tcp``, ``8000-8010``) into ports."""
    value = str(token or "").split("/", 1)[0]
    chunks = value.split("-")
    ports = [int(chunk) for chunk in chunks if chunk.isdigit()]
    if len(chunks) == 2 and len(ports) == 2:
        low, high = sorted(ports)
        if 0 <= high - low <= 64:
            return list(range(low, high + 1))
    return ports


def _package_tokens(packages: str) -> List[str]:
    """Return the package names of an install argument (options removed)."""
    tokens: List[str] = []
    for raw in str(packages or "").replace("\\", " ").split():
        token = raw.strip("\"'")
        if not token or token.startswith("-") or "$" in token:
            continue
        if token in {"&&", "||", ";", "|", ">"}:
            continue
        tokens.append(token)
    return tokens


def _installed_packages(command: str) -> List[str]:
    """Return every package installed by a shell command."""
    found: List[str] = []
    for pattern in INSTALL_PATTERNS:
        for match in pattern.finditer(command):
            found.extend(_package_tokens(match.group("packages")))
    return found


def _is_disabled_healthcheck(argument: str) -> bool:
    """Return ``True`` for ``HEALTHCHECK NONE`` (an explicit opt-out)."""
    return str(argument or "").strip().upper().startswith("NONE")


def _assignments(argument: str, legacy_pairs: bool = False) -> List[Tuple[str, str]]:
    """Return the ``(key, value)`` pairs of an ENV/ARG/LABEL instruction.

    ``legacy_pairs`` handles the ``ENV KEY value`` form, where the value is the
    remainder of the line instead of an ``=`` separated token.
    """
    text = str(argument or "").strip()
    if not text:
        return []
    if "=" not in text:
        if not legacy_pairs:
            return []
        parts = text.split(None, 1)
        if len(parts) != 2:
            return []
        return [(strip_quotes(parts[0]), strip_quotes(parts[1]))]
    pairs: List[Tuple[str, str]] = []
    for token in text.split():
        key, value = split_assignment(token)
        if key:
            pairs.append((key, value))
    return pairs


def _sensitive_copy_reason(source: str) -> str:
    """Return why ``source`` looks like credential material, or ``""``.

    Remote URLs are skipped here: they are reported by ``DF-004`` instead.
    """
    if re.match(r"(?:https?|ftp|git)://|^git@", source, re.IGNORECASE):
        return ""
    cleaned = str(source or "").strip().strip("/")
    if not cleaned or cleaned in {".", "..", "*"}:
        return ""
    parts = [part for part in re.split(r"[\\/]", cleaned) if part and part not in {".", ".."}]
    name = (parts[-1] if parts else cleaned).lower()
    if name in SENSITIVE_COPY_NAMES or name.startswith(".env"):
        return "credential file"
    if any(name.endswith(suffix) for suffix in SENSITIVE_COPY_SUFFIXES):
        return "key material"
    if any(part.lower() in SENSITIVE_COPY_SEGMENTS for part in parts):
        return "credential directory"
    return ""


__all__ = ["DockerfileScanner"]
