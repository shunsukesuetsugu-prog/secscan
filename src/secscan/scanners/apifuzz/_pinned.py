"""Pinned default Schemathesis image digest + helper.

Phase 2-O: ``secscan apifuzz`` runs Schemathesis via Docker. The
Schemathesis container runs as ``uid=1000(schemathesis)`` so a
freshly-created named volume (owned by root) needs to be chowned
before Schemathesis can write its NDJSON report there. We reuse
the same Alpine helper image Phase 2-D (DAST) uses for the ZAP
report volume — the helper runs as root, chowns ``/work`` to
``1000:1000``, and exits.

Rotate the Schemathesis pin when upgrading:

1. ``docker pull schemathesis/schemathesis:<version>``
2. ``docker inspect --format='{{index .RepoDigests 0}}' schemathesis/schemathesis:<version>``
3. Update ``DEFAULT_SCHEMATHESIS_IMAGE`` + ``DEFAULT_PINNED_AT``.
4. Re-run the apifuzz bench to refresh the expected check-name set.
"""

from __future__ import annotations

DEFAULT_SCHEMATHESIS_IMAGE_REPOSITORY = "schemathesis/schemathesis"
DEFAULT_SCHEMATHESIS_IMAGE_DIGEST = (
    "abd96924cce31cc72f3449266dde5c5c927f528a6c7184ac69893ddcf4fe85dc"
)
DEFAULT_SCHEMATHESIS_IMAGE = (
    f"{DEFAULT_SCHEMATHESIS_IMAGE_REPOSITORY}"
    f"@sha256:{DEFAULT_SCHEMATHESIS_IMAGE_DIGEST}"
)

# Reuse the DAST helper alpine pin so we don't have a duplicate
# constant drifting across modules. Imported lazily by the scanner
# to keep this module a leaf.
DEFAULT_HELPER_IMAGE = (
    "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)

DEFAULT_PINNED_AT = "2026-05-24"

# UID/GID Schemathesis 4.x runs as inside the official image.
SCHEMATHESIS_UID = 1000
SCHEMATHESIS_GID = 1000
