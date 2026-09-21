"""Espace de compatibilite : les tests des rendus vivent dans test_reporters.py."""

import unittest

from test_reporters import ReportersTests  # noqa: F401

if __name__ == "__main__":
    unittest.main()
