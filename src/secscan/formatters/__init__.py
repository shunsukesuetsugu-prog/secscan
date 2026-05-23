"""Output formatters.

Each formatter takes a ``(RunResult, PolicyDecision, FormatOptions)`` triple
and returns the serialized string the CLI writes to stdout (or to the
``--output`` file). Formatters are pure: they never read or write anything
beyond their inputs.

Registered formats (matched against the CLI's ``--format`` flag):

- ``text``  — human-readable terminal output (the default).
- ``json``  — secscan-json v1 (a stable structured format we own).
- ``sarif`` — SARIF 2.1.0, suitable for upload to GitHub Code Scanning.

Codex 17th review pinned several invariants:
- All formatters MUST exclude ``Finding.raw`` from output.
- All formatters MUST exclude ``Finding.raw_fingerprint`` (gitleaks-style
  raw fingerprints can carry file paths that bypass orchestrator's
  path-stripping).
- SARIF MUST be valid against the official 2.1.0 schema, and MUST NOT
  include source ``contents`` or ``snippet`` fields.
- ``--quiet`` is text-only; combining with json/sarif is a CLI error.
"""

from __future__ import annotations

from .base import FormatOptions, Formatter, UnknownFormatError, format_for
from .json_format import format_json
from .sarif import format_sarif
from .text import format_text

__all__ = [
    "FormatOptions",
    "Formatter",
    "UnknownFormatError",
    "format_for",
    "format_json",
    "format_sarif",
    "format_text",
]
