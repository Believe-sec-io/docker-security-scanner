"""Heuristics deciding whether a variable name/value looks like a credential.

The scanner must never echo a secret back into a report, so this module works
strictly on *names* and on the *shape* of a value:

* :func:`looks_like_secret_name` decides whether ``DB_PASSWORD`` or
  ``AWS_SECRET_ACCESS_KEY`` deserves a finding.
* :func:`is_literal_value` decides whether the value is a real literal or an
  interpolation (``${DB_PASSWORD}``) that is resolved at run time.
* :func:`redact` produces the placeholder that reporters put in the evidence
  field, so that a scan result can be attached to a ticket without leaking.

The heuristics intentionally err on the side of reporting: a false positive
costs a reviewer ten seconds, a false negative leaks a production credential.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence, Tuple

#: Variable names that usually hold credential material.
SECRET_NAME_PATTERN = re.compile(
    r"(?:"
    r"pass(?:word|wd|phrase)?"
    r"|secret"
    r"|token"
    r"|api[_-]?key"
    r"|access[_-]?key"
    r"|private[_-]?key"
    r"|secret[_-]?key"
    r"|client[_-]?secret"
    r"|credential"
    r"|auth(?:orization)?"
    r"|bearer"
    r"|session[_-]?key"
    r"|signing[_-]?key"
    r"|encryption[_-]?key"
    r"|ssh[_-]?key"
    r"|pgp[_-]?key"
    r"|connection[_-]?string"
    r"|dsn"
    r")",
    re.IGNORECASE,
)

#: Values that look like documentation rather than like a real secret.
PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "null",
        "none",
        "nil",
        "todo",
        "tbd",
        "example",
        "placeholder",
        "changeme",
        "change-me",
        "change_me",
        "replace_me",
        "replaceme",
        "your_password",
        "your-password",
        "your_password_here",
        "password",
        "passw0rd",
        "secret",
        "token",
        "xxx",
        "xxxx",
        "xxxxxx",
        "********",
        "<secret>",
        "<password>",
    }
)

#: ``$VAR`` / ``${VAR}`` interpolation, resolved when the container starts.
_INTERPOLATION = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")

#: Paths that are, by convention, populated from a secret store at run time.
_SECRET_PATH_PREFIXES = (
    "/run/secrets/",
    "/var/run/secrets/",
    "/run/credentials/",
)


def looks_like_secret_name(name: str) -> bool:
    """Return ``True`` when ``name`` reads like a credential variable."""
    candidate = str(name or "").strip()
    if not candidate:
        return False
    return bool(SECRET_NAME_PATTERN.search(candidate))


def is_placeholder(value: str) -> bool:
    """Return ``True`` for documented/obvious dummy values."""
    candidate = str(value or "").strip().strip("\"'").strip()
    if not candidate:
        return True
    if candidate.lower() in PLACEHOLDER_VALUES:
        return True
    # A value made only of the same one or two characters (``xxx``, ``***``) is
    # a placeholder, not a credential.
    if len(set(candidate)) <= 2 and len(candidate) <= 8:
        return True
    return bool(re.fullmatch(r"<[^>]*>", candidate))


def is_interpolation(value: str) -> bool:
    """Return ``True`` when the value is resolved at run time, not hardcoded."""
    candidate = str(value or "").strip().strip("\"'")
    if not candidate:
        return False
    if candidate.startswith(_SECRET_PATH_PREFIXES):
        return True
    return bool(_INTERPOLATION.search(candidate))


def is_literal_value(value: str) -> bool:
    """Return ``True`` when ``value`` is a hardcoded, non-placeholder secret."""
    candidate = str(value or "").strip()
    if not candidate:
        return False
    if is_placeholder(candidate):
        return False
    if is_interpolation(candidate):
        return False
    return True


def split_assignment(text: str) -> Tuple[str, str]:
    """Split ``KEY=value`` into its two parts.

    Returns the name alone and an empty value for the bare ``KEY`` form used by
    Docker Compose (``environment: [KEY]``), and ``("", "")`` when the text is
    not an assignment at all.
    """
    candidate = str(text or "").strip()
    if not candidate:
        return "", ""
    if "=" not in candidate:
        return candidate.strip().strip("\"'"), ""
    name, _, value = candidate.partition("=")
    return name.strip().strip("\"'"), value.strip().strip("\"'")


def redact(value: str) -> str:
    """Return a placeholder describing ``value`` without revealing it.

    Only the length is disclosed, which is enough for a reviewer to confirm
    that a real value is in place without putting it in the report.
    """
    length = len(str(value or ""))
    if not length:
        return "<empty>"
    return f"<redacted {length} chars>"


def find_secret_names(names: Iterable[str]) -> List[str]:
    """Return the subset of ``names`` that look like credentials, sorted."""
    return sorted({name for name in names if looks_like_secret_name(name)})


def inspect_assignments(assignments: Iterable[str]) -> List[Tuple[str, str]]:
    """Return the ``(name, value)`` pairs that carry a literal secret.

    ``assignments`` accepts both the ``KEY=value`` and the bare ``KEY`` forms
    used by Dockerfiles and Compose files.
    """
    found: List[Tuple[str, str]] = []
    for assignment in assignments:
        name, value = split_assignment(assignment)
        if not looks_like_secret_name(name):
            continue
        if not is_literal_value(value):
            continue
        found.append((name, value))
    return found


def first_secret_in_text(text: str) -> Optional[Tuple[str, str]]:
    """Return the first ``KEY=value`` hardcoded secret found in ``text``.

    Used on ``RUN``/``COPY`` command lines, where a variable name cannot be
    isolated from a structured document.
    """
    for token in re.split(r"[\s,;]+", str(text or "")):
        if "=" not in token:
            continue
        name, value = split_assignment(token)
        if looks_like_secret_name(name) and is_literal_value(value):
            return name, value
    return None


def secret_names_in_text(text: str) -> Sequence[str]:
    """Return every credential-looking variable name assigned in ``text``."""
    names = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", str(text or ""))
    return tuple(find_secret_names(names))


__all__ = [
    "PLACEHOLDER_VALUES",
    "SECRET_NAME_PATTERN",
    "find_secret_names",
    "first_secret_in_text",
    "inspect_assignments",
    "is_interpolation",
    "is_literal_value",
    "is_placeholder",
    "looks_like_secret_name",
    "redact",
    "secret_names_in_text",
    "split_assignment",
]
