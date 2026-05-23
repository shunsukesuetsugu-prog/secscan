"""Formatter Protocol + shared options + registry.

Keeping the registry small and explicit (a literal dict) lets each
formatter be a pure function instead of a class hierarchy. The CLI calls
``format_for(name)(...)`` and writes the resulting string.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..models import RunResult
from ..policy import PolicyDecision

# Public name → formatter callable. Populated lazily at import time by the
# formatters/__init__.py module (which imports the concrete formatters and
# registers them via ``_register``).
_REGISTRY: dict[str, Callable[[RunResult, PolicyDecision, FormatOptions], str]] = {}


@dataclass(frozen=True)
class FormatOptions:
    """Options consumed by every formatter.

    Not every field is meaningful for every format — ``use_color`` is text
    only, ``include_suppressed_in_sarif`` is sarif only — but a single
    options object keeps the CLI layer simple.
    """

    use_color: bool = False
    verbose: bool = False
    quiet: bool = False
    include_suppressed_in_sarif: bool = False


# Module-level frozen singleton — re-used as the default arg to avoid the
# B008 lint that flags ``arg=FormatOptions()`` in defaults.
DEFAULT_OPTIONS = FormatOptions()


# Public alias for the formatter callable shape.
Formatter = Callable[[RunResult, PolicyDecision, FormatOptions], str]


class UnknownFormatError(ValueError):
    """Raised when the CLI is asked for a format the registry doesn't know.

    The CLI's argparse ``choices=`` argument should catch this earlier in
    practice; the exception is here so direct ``format_for`` callers also
    fail loudly.
    """


def _register(name: str, formatter: Formatter) -> None:
    """Add ``formatter`` to the registry under ``name``.

    Called from the concrete formatter modules; not part of the public API.
    """
    if name in _REGISTRY:
        raise ValueError(f"formatter name already registered: {name!r}")
    _REGISTRY[name] = formatter


def format_for(name: str) -> Formatter:
    """Look up a formatter by its CLI name."""
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise UnknownFormatError(
            f"unknown format {name!r}; known: {sorted(_REGISTRY)}"
        ) from exc


def known_format_names() -> tuple[str, ...]:
    """Return the sorted tuple of registered format names."""
    return tuple(sorted(_REGISTRY))
