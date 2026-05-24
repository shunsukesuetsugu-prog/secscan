"""CWE-798 fixture: hard-coded credentials.

Expected to be detected by secscan's bundled
``secscan-python-hardcoded-credential`` rule. The value is
deliberately a credential-shaped string so the rule fires — it is
NOT a real password (this file is a benchmark fixture; the comment
above ``DB_PASSWORD`` documents that for any human reader).
"""

from __future__ import annotations

# CWE-798: hard-coded credential. NOT a real password — a synthetic
# benchmark string used to verify secscan's SAST detection.
DB_PASSWORD = "ZqL9bN3kR7mV2pX1"


def connect() -> dict[str, str]:
    return {"user": "admin", "password": DB_PASSWORD}
