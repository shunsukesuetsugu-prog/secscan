"""Process exit codes.

The split between code 1 and code 2 is deliberate and CI-relevant:

- 0  : scan ran to completion; no findings at-or-above the configured
       severity threshold remained after baseline suppression.
- 1  : scan ran to completion; findings at-or-above the threshold remained.
       Treat as "policy violation".
- 2  : scan did NOT run to completion. Tool failure, config error, missing
       lockfile (without ``--allow-missing-lockfile``), unreadable path,
       internal exception, etc. Treat as "scan inconclusive".
- 130: user interrupt (SIGINT / Ctrl-C). Matches shell convention.

Code 1 vs 2 must never overlap. In ``all`` mode, if any scanner is
inconclusive AND others find issues, the more severe code (2) wins so CI
operators do not mistake an inconclusive scan for a clean one.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    OK = 0
    FINDINGS = 1
    SCAN_ERROR = 2
    INTERRUPTED = 130
