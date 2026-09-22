#!/usr/bin/env python3
"""Entry point of the Docker security scanner.

Two ways to run the tool, both documented in the README::

    python main.py                # from a checkout
    docker-security-scanner       # once installed (pip install -e .)
"""

from __future__ import annotations

import sys

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
