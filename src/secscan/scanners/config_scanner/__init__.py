"""Configuration / IaC scanner (Trivy).

Phase 2-L: ``secscan config`` invokes Aqua Security's Trivy via
Docker to check Kubernetes manifests, Terraform / OpenTofu, Dockerfiles,
and Helm charts for security misconfigurations. The scanner mirrors
the DAST scanner's docker-based architecture but is much simpler
because Trivy config-scan is purely read-only.

Public surface:

- :class:`ConfigScanner` — the Scanner subclass the CLI registers.
- ``build_argv`` / ``parse_trivy_report`` — pure helpers for tests.
- ``validate_image_ref`` / ``validate_scan_path`` — input validators.
"""

from __future__ import annotations

from .scanner import ConfigScanner
from .trivy import (
    ConfigInputError,
    TrivyInvocation,
    TrivyReportParse,
    build_argv,
    classify_trivy_exit,
    parse_trivy_report,
    validate_image_ref,
    validate_scan_path,
)

__all__ = [
    "ConfigInputError",
    "ConfigScanner",
    "TrivyInvocation",
    "TrivyReportParse",
    "build_argv",
    "classify_trivy_exit",
    "parse_trivy_report",
    "validate_image_ref",
    "validate_scan_path",
]
