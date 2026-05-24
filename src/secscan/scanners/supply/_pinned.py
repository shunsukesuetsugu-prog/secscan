"""Pinned default Cosign image for supply-chain verification.

Phase 2-Q: ``secscan supply --verify-image`` runs Sigstore cosign
via Docker. The cosign binary itself is shipped as
``gcr.io/projectsigstore/cosign:vX.Y.Z`` by the Sigstore project.

Pin rotation strategy (Codex Phase 2-Q design review MUST-FIX #5):

The Sigstore project rotates the embedded TUF trust material in
new cosign releases — newer signed images sometimes require a
newer cosign to verify. Operators who hit a verification failure
that says ``unable to obtain Sigstore trust material`` should:

1. ``docker pull gcr.io/projectsigstore/cosign:<new-version>``
2. ``docker inspect --format='{{index .RepoDigests 0}}' ...``
3. Pass the digest via ``--cosign-image <repo>@sha256:<digest>``
   (CLI override, digest-pinned form required).
4. Optional: open a PR updating the constants below.

The CLI override is **digest-pinned only** — tag-only references
like ``gcr.io/projectsigstore/cosign:v2.4.2`` are rejected so an
attacker who can edit ``--cosign-image`` cannot point us at a
mutable tag that resolves differently every time.
"""

from __future__ import annotations

DEFAULT_COSIGN_IMAGE_REPOSITORY = "gcr.io/projectsigstore/cosign"
DEFAULT_COSIGN_VERSION = "v2.4.1"

# Digest of cosign v2.4.1 as published to gcr.io (pulled and
# verified on the Phase 2-Q development host).
DEFAULT_COSIGN_IMAGE_DIGEST = (
    "b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31"
)

DEFAULT_COSIGN_IMAGE = (
    f"{DEFAULT_COSIGN_IMAGE_REPOSITORY}@sha256:{DEFAULT_COSIGN_IMAGE_DIGEST}"
)

DEFAULT_PINNED_AT = "2026-05-24"

# Maximum total time for one cosign verify invocation: TUF root
# refresh + image manifest fetch + Rekor transparency-log query +
# signature math. Defaults to 60s — keyless verify against a
# typical container image finishes in 2-5 seconds; we give a
# wide cap for slow / proxied networks.
DEFAULT_COSIGN_TIMEOUT_SECONDS = 60

# Maximum file size for a lockfile we'll parse. Even a huge
# monorepo's ``package-lock.json`` rarely tops 20 MiB; this is
# the same 32 MiB cap as every other phase.
MAX_LOCKFILE_BYTES = 32 * 1024 * 1024

# Maximum size of cosign JSON stdout we'll read. cosign produces
# a small (< 100 KiB) JSON blob per verification; we cap at 4 MiB
# to bound memory while leaving 40x headroom.
MAX_COSIGN_STDOUT_BYTES = 4 * 1024 * 1024
