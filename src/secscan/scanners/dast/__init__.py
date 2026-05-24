"""DAST (Dynamic Application Security Testing) via OWASP ZAP.

Phase 2-D scanner. The scanner wraps the ``zaproxy/zap-stable`` Docker
image's ``zap-baseline.py`` and normalizes its JSON report into secscan
``Finding`` instances.

Public surface:

- ``DastScanner``: the :class:`secscan.scanners.base.Scanner` subclass
  the CLI registers.
- ``build_argv``: pure helper that constructs the ``docker run`` argv
  list (testable without invoking docker).
- ``parse_zap_report``: pure helper that converts a ZAP JSON report
  blob into Findings (testable with canned bytes).
- ``validate_image_ref`` / ``validate_target_url``: input validators
  surfaced for direct unit testing of the security boundary.

Design notes and review history live in
``docs/_design/phase2d_dast_design.md``.
"""

from __future__ import annotations

from .scanner import DastScanner
from .zap import (
    build_argv,
    parse_zap_report,
    validate_image_ref,
    validate_target_url,
)

__all__ = [
    "DastScanner",
    "build_argv",
    "parse_zap_report",
    "validate_image_ref",
    "validate_target_url",
]
