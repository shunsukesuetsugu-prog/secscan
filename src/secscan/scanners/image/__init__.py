"""Container image vulnerability scanner (Trivy image mode).

Phase 2-M: ``secscan image --image <repo[:tag]@sha256:digest>``
runs Trivy in image mode against one or more digest-pinned OCI
images. Detects OS-package and language-package CVEs that the
source-tree-based scanners (deps / sast / secrets) cannot see.

Like DAST, it is **opt-in**: ``secscan all`` only runs it when
``[image].refs`` is non-empty in ``.secscan.toml`` (or
``--image`` is passed on the CLI).

Public surface:

- :class:`ImageScanner` — Scanner subclass registered by the CLI.
- ``build_argv`` / ``build_db_seed_argv`` / ``parse_trivy_image_report``
  — pure helpers, unit-tested without docker.
- ``validate_image_ref`` / ``validate_platform`` /
  ``validate_cache_volume`` — input validators.
"""

from __future__ import annotations

from ._pinned import (
    DEFAULT_TARGET_PLATFORM,
    DEFAULT_TRIVY_IMAGE,
    DEFAULT_TRIVY_IMAGE_DIGEST,
    DEFAULT_TRIVY_IMAGE_PINNED_AT,
    DEFAULT_TRIVY_IMAGE_REPOSITORY,
    TRIVY_CACHE_VOLUME,
)
from .scanner import ImageScanner
from .trivy import (
    ImageInputError,
    TrivyImageInvocation,
    TrivyImageReportParse,
    build_argv,
    build_db_seed_argv,
    classify_trivy_image_exit,
    parse_trivy_image_report,
    validate_cache_volume,
    validate_image_ref,
    validate_platform,
)

__all__ = [
    "DEFAULT_TARGET_PLATFORM",
    "DEFAULT_TRIVY_IMAGE",
    "DEFAULT_TRIVY_IMAGE_DIGEST",
    "DEFAULT_TRIVY_IMAGE_PINNED_AT",
    "DEFAULT_TRIVY_IMAGE_REPOSITORY",
    "TRIVY_CACHE_VOLUME",
    "ImageInputError",
    "ImageScanner",
    "TrivyImageInvocation",
    "TrivyImageReportParse",
    "build_argv",
    "build_db_seed_argv",
    "classify_trivy_image_exit",
    "parse_trivy_image_report",
    "validate_cache_volume",
    "validate_image_ref",
    "validate_platform",
]
