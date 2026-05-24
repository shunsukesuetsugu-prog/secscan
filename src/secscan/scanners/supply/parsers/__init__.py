"""Per-ecosystem lockfile parsers.

Phase 2-Q ships parsers for npm / pip / uv. yarn / pnpm /
cargo / go.sum will be added in a future phase.

Each parser exposes a single function ``check_<ecosystem>(text:
str) -> tuple[list[Issue], dict[str, object]]`` that:

1. Loads the lockfile from text (no I/O — the dispatcher reads
   the file and passes the contents in, so we can unit-test
   without a fixture file on disk).
2. Walks the structure looking for self-consistency anomalies.
3. Returns a list of ``Issue`` records and a tool-version-style
   dict the dispatcher can promote into ``ScanOutcome.warnings``
   for things that don't quite rise to a Finding.
"""

from __future__ import annotations

from .npm import check_npm_lockfile
from .pip import check_pipfile_lock
from .uv import check_uv_lock

__all__ = [
    "check_npm_lockfile",
    "check_pipfile_lock",
    "check_uv_lock",
]
