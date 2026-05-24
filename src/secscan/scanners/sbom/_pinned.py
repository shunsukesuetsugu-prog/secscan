"""Pinned default Syft + Grype image digests.

Phase 2-N: ``secscan sbom`` runs Anchore's Syft (SBOM generator)
followed by Grype (CVE matcher) — two separate containers.

Both pins are **multi-arch index digests** (not per-arch manifest
digests). Reason: the Syft 1.x / Grype 0.x line ships a Go runtime
crash under Rosetta translation on Apple Silicon, so secscan does
NOT pass ``--platform`` to ``docker run`` for these images; docker
picks the host-native variant automatically.

Reproducibility on the *target* image side is preserved by passing
``--platform`` to the Syft CLI itself when the target is an OCI
image ref (Syft accepts ``--platform linux/amd64`` and inspects
the matching manifest of a multi-arch index without needing the
scanner container to also run on that arch).

Rotate these constants when upgrading:

1. ``docker pull anchore/syft:<version>`` (and similarly for grype)
2. ``docker inspect --format='{{index .RepoDigests 0}}' anchore/syft:<version>``
3. Update ``DEFAULT_SYFT_IMAGE`` / ``DEFAULT_GRYPE_IMAGE`` here.
4. Re-run the sbom bench to refresh the expected CVE-ID sets.
"""

from __future__ import annotations

DEFAULT_SYFT_IMAGE_REPOSITORY = "anchore/syft"
DEFAULT_SYFT_IMAGE_DIGEST = (
    "86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
)
DEFAULT_SYFT_IMAGE = (
    f"{DEFAULT_SYFT_IMAGE_REPOSITORY}@sha256:{DEFAULT_SYFT_IMAGE_DIGEST}"
)

DEFAULT_GRYPE_IMAGE_REPOSITORY = "anchore/grype"
DEFAULT_GRYPE_IMAGE_DIGEST = (
    "391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d"
)
DEFAULT_GRYPE_IMAGE = (
    f"{DEFAULT_GRYPE_IMAGE_REPOSITORY}@sha256:{DEFAULT_GRYPE_IMAGE_DIGEST}"
)

DEFAULT_PINNED_AT = "2026-05-24"

# Reserved Grype cache-volume name used by ``bench/run.py`` to
# pre-seed Grype's vulnerability DB once per bench run. Mirrors the
# Phase 2-M ``TRIVY_CACHE_VOLUME`` pattern.
GRYPE_CACHE_VOLUME = "secscan-grype-cache"

# Default platform forwarded to **Syft CLI** when the target is an
# OCI image ref. NOT used on ``docker run`` (see module docstring).
DEFAULT_TARGET_PLATFORM = "linux/amd64"
