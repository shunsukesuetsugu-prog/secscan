"""Compatibility shim — terminal report rendering moved to ``formatters/text.py``.

Phase 2-A split the text rendering out into the formatters package so JSON
and SARIF can share the same ``(RunResult, PolicyDecision, options)``
contract. The names below preserve the Phase 1 public surface so external
callers (and a fair chunk of the test suite) don't have to be rewritten:

- ``ReportOptions``  → alias for ``formatters.base.FormatOptions``
- ``render_report``  → alias for ``formatters.text.format_text``
- ``render_baseline_application`` → re-exported from ``formatters.text``

New code should import from ``secscan.formatters`` directly.
"""

from __future__ import annotations

from .formatters.base import FormatOptions as ReportOptions
from .formatters.text import format_text as render_report
from .formatters.text import render_baseline_application

__all__ = ["ReportOptions", "render_baseline_application", "render_report"]
