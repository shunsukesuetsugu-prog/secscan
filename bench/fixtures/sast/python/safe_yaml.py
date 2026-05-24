"""Borderline-clean counterpart to cwe502_yaml_load.py.

Uses yaml.safe_load (the documented safe pattern).
"""

from __future__ import annotations

import yaml


def load_config_safely(blob: str) -> object:
    # NOT a CWE-502: safe_load forbids arbitrary object instantiation.
    return yaml.safe_load(blob)
