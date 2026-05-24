"""CWE-502 fixture: deserialization of untrusted YAML.

Expected to be detected by p/python rules that flag yaml.load without
SafeLoader.
"""

from __future__ import annotations

import yaml


def load_config(blob: str) -> object:
    # CWE-502: yaml.load without SafeLoader → arbitrary object instantiation.
    return yaml.load(blob)  # noqa: S506
