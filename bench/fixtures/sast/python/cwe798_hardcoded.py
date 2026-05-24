"""CWE-798 fixture: hard-coded credentials.

Expected to be detected by p/secrets or p/python rules.
The value is itself an obvious example placeholder so it cannot be
used against a real service.
"""

from __future__ import annotations

# CWE-798: hard-coded credential. Not a real secret.
DB_PASSWORD = "hunter2-example-placeholder"  # noqa: S105


def connect() -> dict[str, str]:
    return {"user": "admin", "password": DB_PASSWORD}
