"""Supply-chain integrity scanner (Phase 2-Q).

Two verification paths, both opt-in:

1. **Cosign image signature verify** (keyless flow only in
   v0.18.0). ``secscan supply --verify-image <ref>
   --signer-identity <id> --signer-issuer <url>`` runs Sigstore
   cosign in a hardened container to confirm the image was
   signed by the expected publisher.
2. **Lockfile self-consistency** (offline; no docker). Reads
   npm ``package-lock.json``, ``Pipfile.lock``, and ``uv.lock``
   and reports anomalies in the SRI / sha256 hash fields,
   cross-entry mismatches, and non-canonical registry URLs.

Cosign failures are classified into 4 rule IDs (Codex Phase
2-Q design review MUST-FIX):

- ``cosign-signature-missing`` (MEDIUM)
- ``cosign-identity-mismatch`` (HIGH)
- ``cosign-signature-invalid`` (HIGH)
- ``cosign-verification-network-failure`` (LOW)

Key-based cosign verification (``--key cosign.pub``) and yarn /
pnpm / cargo / go.sum lockfile parsers are deferred to a
future phase.
"""

from __future__ import annotations

from ._pinned import (
    DEFAULT_COSIGN_IMAGE,
    DEFAULT_COSIGN_IMAGE_DIGEST,
    DEFAULT_COSIGN_IMAGE_REPOSITORY,
    DEFAULT_COSIGN_TIMEOUT_SECONDS,
    DEFAULT_COSIGN_VERSION,
    DEFAULT_PINNED_AT,
    MAX_COSIGN_STDOUT_BYTES,
    MAX_LOCKFILE_BYTES,
)
from .cosign import (
    CosignParse,
    CosignVerification,
    build_argv,
    classify_cosign_failure,
    finding_for_cosign_failure,
    parse_cosign_success,
    severity_for_rule,
)
from .lockfile import LockfileParse, check_lockfile
from .scanner import CosignTargetSpec, SupplyScanner, SupplyScannerSettings
from .validators import (
    LockfileTarget,
    SupplyInputError,
    classify_lockfile,
    validate_image_ref,
    validate_signer_identity,
    validate_signer_identity_regexp,
    validate_signer_issuer,
)

__all__ = [
    "DEFAULT_COSIGN_IMAGE",
    "DEFAULT_COSIGN_IMAGE_DIGEST",
    "DEFAULT_COSIGN_IMAGE_REPOSITORY",
    "DEFAULT_COSIGN_TIMEOUT_SECONDS",
    "DEFAULT_COSIGN_VERSION",
    "DEFAULT_PINNED_AT",
    "MAX_COSIGN_STDOUT_BYTES",
    "MAX_LOCKFILE_BYTES",
    "CosignParse",
    "CosignTargetSpec",
    "CosignVerification",
    "LockfileParse",
    "LockfileTarget",
    "SupplyInputError",
    "SupplyScanner",
    "SupplyScannerSettings",
    "build_argv",
    "check_lockfile",
    "classify_cosign_failure",
    "classify_lockfile",
    "finding_for_cosign_failure",
    "parse_cosign_success",
    "severity_for_rule",
    "validate_image_ref",
    "validate_signer_identity",
    "validate_signer_identity_regexp",
    "validate_signer_issuer",
]
