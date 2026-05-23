"""Filesystem boundary enforcement.

secscan touches arbitrary user-supplied paths and consumes file paths from
external tools (semgrep, gitleaks). Two threats motivate this module:

1. ``--path`` itself may be relative, a symlink, or point outside the
   intended repository. We resolve it to an absolute, real path before
   anything else uses it.
2. Tools may return paths that traverse symlinks out of the scan root, or
   reference files in ignored directories (``.venv``, ``node_modules``).
   Any reported finding must be re-checked against the scan root and
   ignore list, because the tools' own --exclude flags are not always
   honored consistently.

Codex flagged both. We do not "trust" the tool to stay inside ``--path``.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        # Version control
        ".git",
        ".hg",
        ".svn",
        # Python virtual environments / caches
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        # Node ecosystems
        "node_modules",
        ".pnpm-store",
        ".yarn",
        ".next",
        ".nuxt",
        ".turbo",
        ".parcel-cache",
        # Build outputs
        "dist",
        "build",
        "out",
        "target",
        # Test / coverage outputs
        "coverage",
        ".coverage",
        "htmlcov",
        # IDE
        ".idea",
        ".vscode",
        # Misc
        "vendor",
        "tmp",
    }
)


class PathSafetyError(ValueError):
    """Raised when --path or a reported path violates safety constraints."""


@dataclass(frozen=True)
class ResolvedRoot:
    """A vetted scan root.

    ``original`` is what the user typed; ``resolved`` is the real,
    absolute path with symlinks expanded. Reporters display ``original``
    so the user sees what they asked for; internal logic uses
    ``resolved`` so containment checks are unambiguous.
    """

    original: Path
    resolved: Path
    ignore_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_IGNORE_DIRS)

    def contains(self, candidate: Path) -> bool:
        """Whether ``candidate`` lies under this root after symlink expansion."""
        try:
            real = candidate.resolve(strict=False)
        except OSError:
            return False
        try:
            real.relative_to(self.resolved)
        except ValueError:
            return False
        return True

    def is_ignored(self, candidate: Path) -> bool:
        """Whether any path component matches an ignored directory name.

        We check by name, not by full path, so the ignore set works at any
        depth (e.g. ``packages/foo/node_modules/...`` is ignored).
        """
        try:
            real = candidate.resolve(strict=False)
        except OSError:
            return True  # Unreadable -> treat as ignored
        try:
            rel = real.relative_to(self.resolved)
        except ValueError:
            return True  # Outside root -> ignored
        return any(part in self.ignore_dirs for part in rel.parts)

    def relativize(self, candidate: Path) -> str:
        """Return a forward-slash relative path string for display.

        Falls back to the absolute path string if the candidate is not
        under the root — but this should never happen for paths that
        passed ``contains()``.
        """
        try:
            real = candidate.resolve(strict=False)
            rel = real.relative_to(self.resolved)
            return rel.as_posix()
        except (OSError, ValueError):
            return str(candidate).replace(os.sep, "/")


def resolve_scan_root(
    path: str | os.PathLike[str],
    *,
    extra_ignore_dirs: Iterable[str] = (),
) -> ResolvedRoot:
    """Validate and resolve a user-supplied scan root.

    Raises ``PathSafetyError`` if the path does not exist, is not a directory,
    or cannot be resolved. The strict=True resolve ensures we fail loudly on
    broken symlinks rather than silently scanning the wrong thing.
    """
    original = Path(path)
    try:
        resolved = original.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PathSafetyError(f"--path does not exist: {original}") from exc
    except OSError as exc:
        raise PathSafetyError(f"--path could not be resolved: {original} ({exc})") from exc

    if not resolved.is_dir():
        raise PathSafetyError(f"--path is not a directory: {original}")

    ignore_dirs = frozenset(DEFAULT_IGNORE_DIRS | set(extra_ignore_dirs))
    return ResolvedRoot(original=original, resolved=resolved, ignore_dirs=ignore_dirs)
