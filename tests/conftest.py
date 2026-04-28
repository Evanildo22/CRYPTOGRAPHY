"""
conftest.py — pytest configuration for secure-file-share tests.

Ensures the project root is on sys.path so that ``import crypto`` and
``import audit`` resolve correctly regardless of how pytest is invoked.
"""

import sys
from pathlib import Path

# Add project root to the import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
