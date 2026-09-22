"""Pytest configuration: make the repository importable without installing it.

The package lives in ``src/`` and is imported as ``src.<module>`` from both the
scanner entry point and the tests, so the repository root only has to be on
``sys.path``. Keeping this in a root ``conftest.py`` means ``pytest`` works from
a fresh clone with no environment variable and no editable install.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: Directory holding the insecure/hardened sample configurations.
EXAMPLES = ROOT / "examples"


@pytest.fixture(scope="session")
def examples_dir() -> Path:
    """Absolute path of the ``examples/`` directory."""
    return EXAMPLES
