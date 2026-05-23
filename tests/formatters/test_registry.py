"""Tests for the formatters registry.

Cheap sanity checks: every advertised format is registered, lookup
errors are well-typed, and unknown names fail loudly. The per-format
output assertions live in the dedicated test files.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from secscan.formatters import (
    FormatOptions,
    UnknownFormatError,
    format_for,
    format_json,
    format_sarif,
    format_text,
)
from secscan.formatters.base import known_format_names


def test_registry_advertises_three_formats() -> None:
    assert set(known_format_names()) == {"text", "json", "sarif"}


def test_format_for_returns_registered_callable() -> None:
    assert format_for("text") is format_text
    assert format_for("json") is format_json
    assert format_for("sarif") is format_sarif


def test_format_for_unknown_name_raises_descriptive_error() -> None:
    with pytest.raises(UnknownFormatError) as exc_info:
        format_for("unsupported")
    msg = str(exc_info.value)
    # Error must list the supported set so the user can self-correct.
    assert "unsupported" in msg
    assert "text" in msg


def test_format_options_defaults_are_immutable() -> None:
    """FormatOptions is frozen so callers can safely share a singleton."""
    opts = FormatOptions()
    with pytest.raises(FrozenInstanceError):
        opts.use_color = True  # type: ignore[misc]
