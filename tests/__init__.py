"""Tests unitaires du Docker Security Scanner (bibliotheque standard uniquement).

Lancement depuis la racine du projet :
    python -m unittest discover -s tests -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
