"""SBOM-based vulnerability scanner (Syft + Grype).

Phase 2-N: ``secscan sbom --target <T>`` generates a CycloneDX SBOM
with Anchore Syft and then matches the SBOM against the Grype
vulnerability database. Targets may be local directories
(``/opt/venv``), digest-pinned OCI image refs, or pre-existing SBOM
JSON files (CycloneDX / SPDX). Covers the source-tree-vs-installed
gap that ``deps`` (lockfile only) and ``image`` (built image only)
miss.

Public surface:

- :class:`SbomScanner` — Scanner subclass registered by the CLI.
- ``classify_target`` / ``Target`` union — pure input classifier.
- ``syft.build_argv`` / ``grype.build_argv`` — pure docker argv
  helpers, unit-tested without docker.
- ``grype.parse_grype_report`` — pure JSON → Finding helper.
"""

from __future__ import annotations

from ._pinned import (
    DEFAULT_GRYPE_IMAGE,
    DEFAULT_GRYPE_IMAGE_DIGEST,
    DEFAULT_GRYPE_IMAGE_REPOSITORY,
    DEFAULT_PINNED_AT,
    DEFAULT_SYFT_IMAGE,
    DEFAULT_SYFT_IMAGE_DIGEST,
    DEFAULT_SYFT_IMAGE_REPOSITORY,
    DEFAULT_TARGET_PLATFORM,
    GRYPE_CACHE_VOLUME,
)
from .grype import (
    SBOM_FILE_MOUNT,
    GrypeInvocation,
    GrypeReportParse,
    build_db_seed_argv,
    classify_grype_exit,
    parse_grype_report,
)
from .grype import (
    build_argv as grype_build_argv,
)
from .scanner import SbomScanner
from .syft import (
    SBOM_OUT_PATH,
    SyftInvocation,
    classify_syft_exit,
)
from .syft import (
    build_argv as syft_build_argv,
)
from .validators import (
    MAX_SBOM_BYTES,
    DirectoryTarget,
    ImageTarget,
    SbomFileTarget,
    SbomInputError,
    Target,
    assert_target_under_scan_root,
    classify_target,
    validate_cache_volume_name,
    validate_intermediate_volume_name,
    validate_platform,
)

__all__ = [
    "DEFAULT_GRYPE_IMAGE",
    "DEFAULT_GRYPE_IMAGE_DIGEST",
    "DEFAULT_GRYPE_IMAGE_REPOSITORY",
    "DEFAULT_PINNED_AT",
    "DEFAULT_SYFT_IMAGE",
    "DEFAULT_SYFT_IMAGE_DIGEST",
    "DEFAULT_SYFT_IMAGE_REPOSITORY",
    "DEFAULT_TARGET_PLATFORM",
    "GRYPE_CACHE_VOLUME",
    "MAX_SBOM_BYTES",
    "SBOM_FILE_MOUNT",
    "SBOM_OUT_PATH",
    "DirectoryTarget",
    "GrypeInvocation",
    "GrypeReportParse",
    "ImageTarget",
    "SbomFileTarget",
    "SbomInputError",
    "SbomScanner",
    "SyftInvocation",
    "Target",
    "assert_target_under_scan_root",
    "build_db_seed_argv",
    "classify_grype_exit",
    "classify_syft_exit",
    "classify_target",
    "grype_build_argv",
    "parse_grype_report",
    "syft_build_argv",
    "validate_cache_volume_name",
    "validate_intermediate_volume_name",
    "validate_platform",
]
