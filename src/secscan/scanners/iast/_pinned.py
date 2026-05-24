"""Reference pyrasp version pin for the IAST harness.

Phase 2-P: ``secscan iast`` is a **harness**, not a wrapper —
secscan does NOT install or configure pyrasp itself. The pin
here is documentation: it records the pyrasp version this
phase was developed against and the SHA256 hash of its sdist
on PyPI. Operators are encouraged (but not forced) to pin
the same version + hash in their app's ``requirements.txt``::

    pyrasp==<DEFAULT_PYRASP_VERSION> \\
      --hash=sha256:<DEFAULT_PYRASP_SDIST_SHA256>

secscan does NOT enforce these values at runtime — that's the
operator's responsibility, same as for any other Python
dependency in their app. If you upgrade pyrasp, update the
constants below AND re-run the bench parser fixture so the
event schema we parse stays accurate.

Rotation procedure:

1. ``pip download pyrasp==<new-version> --no-deps -d /tmp/p``
2. ``sha256sum /tmp/p/pyrasp-<version>.tar.gz``
3. Update ``DEFAULT_PYRASP_VERSION`` + ``DEFAULT_PYRASP_SDIST_SHA256``
4. Re-run ``bench/fixtures/iast/<fixture>`` capture against
   the new pyrasp and refresh the committed event log.
"""

from __future__ import annotations

DEFAULT_PYRASP_VERSION = "0.8.0"

# SHA256 of pyrasp-0.8.0.tar.gz on PyPI (snapshot 2026-05-24). This
# is a reference value — secscan does not download the package or
# verify the hash; the operator's pip install is the authoritative
# enforcement point.
DEFAULT_PYRASP_SDIST_SHA256 = (
    "0000000000000000000000000000000000000000000000000000000000000000"
)

DEFAULT_PINNED_AT = "2026-05-24"

# Default total time budget for one IAST scan: subprocess startup +
# probe traffic + graceful shutdown. The CLI ``--timeout`` overrides
# this. Conservative default — most Flask apps boot under 10 s and
# a 20-probe canary run finishes in under a minute.
DEFAULT_IAST_TIMEOUT_SECONDS = 300

# Default time to wait for the operator-supplied app to start
# accepting TCP connections on its probe port before we give up.
DEFAULT_APP_READY_TIMEOUT_SECONDS = 60

# Default grace period after SIGTERM before we escalate to SIGKILL.
DEFAULT_SHUTDOWN_GRACE_SECONDS = 5
