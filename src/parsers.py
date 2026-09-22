"""Low-level parsing helpers shared by every scanner.

Everything in this module is pure: it takes text or a path and returns plain
Python data structures. Keeping the parsing separate from the rule evaluation
makes the scanners easy to unit test with inline strings, without touching the
filesystem or a Docker daemon.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

#: A Dockerfile instruction: ``(line number, instruction, argument)``.
Instruction = Tuple[int, str, str]

#: Instructions that may be continued with a trailing backslash.
_CONTINUATION = "\\"


def read_text(path: str) -> str:
    """Read a text file, tolerating a UTF-8 BOM and non-UTF-8 bytes."""
    raw = Path(path).read_bytes()
    return raw.decode("utf-8-sig", errors="replace")


def join_continuations(text: str) -> List[Tuple[int, str]]:
    """Merge backslash-continued lines, keeping the first line number.

    Returns a list of ``(line_number, logical_line)`` where comments (lines
    whose first non-space character is ``#``) are dropped. A comment inside a
    continued instruction does not terminate it, matching the behaviour of
    BuildKit.
    """
    logical: List[Tuple[int, str]] = []
    buffer = ""
    start = 0

    for number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            # Comments and blank lines never join the instruction: BuildKit
            # strips them before parsing, so appending their text here would
            # make a rule scan a comment as if it were a real command.
            continue
        if not buffer:
            start = number
        if stripped.endswith(_CONTINUATION):
            buffer += stripped[: -len(_CONTINUATION)].rstrip() + " "
            continue
        buffer += stripped
        logical.append((start, buffer.strip()))
        buffer = ""

    if buffer:
        logical.append((start, buffer.strip()))
    return logical


def parse_dockerfile(text: str) -> List[Instruction]:
    """Split a Dockerfile into ``(line, instruction, argument)`` triples.

    Instruction names are upper-cased; arguments keep their original spelling.
    Lines that do not look like an instruction (continuation of a RUN heredoc,
    for instance) are ignored instead of raising, because a linter must stay
    useful on unusual but valid files.
    """
    instructions: List[Instruction] = []
    for number, line in join_continuations(text):
        parts = line.split(None, 1)
        if not parts:
            continue
        name = parts[0].upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            continue
        argument = parts[1].strip() if len(parts) > 1 else ""
        instructions.append((number, name, argument))
    return instructions


def instructions_of(instructions: Sequence[Instruction], name: str) -> List[Instruction]:
    """Return every instruction matching ``name`` (case-insensitive)."""
    wanted = name.upper()
    return [item for item in instructions if item[1] == wanted]


def parse_json_text(text: str) -> Any:
    """Parse JSON text, raising a ``ValueError`` with a readable message."""
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc


def load_json(path: str) -> Any:
    """Load a JSON document from disk (``docker inspect`` output, ``daemon.json``)."""
    return parse_json_text(read_text(path))


def parse_yaml_text(text: str) -> Any:
    """Parse YAML text, raising a ``ValueError`` with a readable message.

    ``yaml.safe_load`` is used on purpose: a configuration file coming from a
    repository must never be able to instantiate arbitrary Python objects.
    """
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc


def as_mapping(value: Any) -> Dict[str, Any]:
    """Return ``value`` as a dict, or an empty dict when it is not a mapping.

    Compose files are full of ``key:`` entries that may be null, a scalar or a
    list; the scanners only care about mappings and must not crash otherwise.
    """
    return dict(value) if isinstance(value, dict) else {}


def as_sequence(value: Any) -> List[Any]:
    """Return ``value`` as a list, wrapping scalars and dropping ``None``."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def as_text_list(value: Any) -> List[str]:
    """Return ``value`` as a list of trimmed strings (empty entries removed).

    ``None`` entries are dropped rather than rendered as ``"None"``: a Compose
    file or a ``docker inspect`` document regularly contains ``null`` inside a
    list (``- CAP_NET_ADMIN`` with no value, an optional ``security_opt``), and
    a literal ``"None"`` would then be scanned as if it were a real setting.
    """
    return [
        text
        for text in (
            str(item).strip() for item in as_sequence(value) if item is not None
        )
        if text
    ]


def as_bool(value: Any) -> bool:
    """Interpret a YAML/JSON value as a boolean the way Docker does.

    ``"yes"``, ``"on"``, ``"1"`` and ``"true"`` are true; anything else is
    false, including the string ``"false"``.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def find_line(text: str, pattern: str, flags: int = re.IGNORECASE) -> int:
    """Return the 1-based line number of the first regex match, or ``0``.

    Used to point a finding at the exact line of a YAML document, since PyYAML
    does not expose line numbers for the nodes it produces.
    """
    compiled = re.compile(pattern, flags)
    for number, line in enumerate(text.splitlines(), start=1):
        if compiled.search(line):
            return number
    return 0


def iter_files(root: str, names: Iterable[str] = (), suffixes: Iterable[str] = ()) -> List[str]:
    """Collect files under ``root`` (or return ``[root]`` when it is a file).

    ``names`` matches file names exactly (case-insensitive), ``suffixes``
    matches extensions. Results are sorted so that reports are reproducible.
    """
    path = Path(root)
    if path.is_file():
        return [str(path)]

    wanted_names = {name.lower() for name in names}
    wanted_suffixes = {suffix.lower() for suffix in suffixes}
    found: List[str] = []

    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file():
            continue
        if wanted_names and candidate.name.lower() in wanted_names:
            found.append(str(candidate))
        elif wanted_suffixes and candidate.suffix.lower() in wanted_suffixes:
            found.append(str(candidate))
    return found


def strip_quotes(value: str) -> str:
    """Remove one pair of matching single or double quotes around ``value``."""
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def first_token(value: str) -> str:
    """Return the first whitespace-separated token of ``value``."""
    parts = value.split()
    return parts[0] if parts else ""


def unquote_command(argument: str) -> Optional[List[str]]:
    """Return the JSON-array form of a CMD/ENTRYPOINT argument.

    ``None`` means the argument is in shell form (or is not a JSON array at
    all), which is exactly what the ``DF-015`` rule reports.
    """
    text = argument.strip()
    if not text.startswith("["):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed):
        return parsed
    return None

