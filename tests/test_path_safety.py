"""Tests for filesystem boundary enforcement.

We verify:
- resolve_scan_root rejects non-existent / file / unresolvable paths.
- Symlinks are resolved at root-resolution time.
- ResolvedRoot.contains rejects sibling and parent paths.
- ResolvedRoot.is_ignored matches by any-depth component, not full path.
- Custom extra_ignore_dirs are added on top of defaults.
"""

from __future__ import annotations

import os
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from secscan.path_safety import (
    DEFAULT_IGNORE_DIRS,
    PathSafetyError,
    ResolvedRoot,
    resolve_scan_root,
)

# --- resolve_scan_root -----------------------------------------------------


def test_resolve_scan_root_accepts_existing_directory(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path)
    assert root.resolved == tmp_path.resolve()
    assert root.original == tmp_path


def test_resolve_scan_root_rejects_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(PathSafetyError, match="does not exist"):
        resolve_scan_root(missing)


def test_resolve_scan_root_rejects_file(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(PathSafetyError, match="not a directory"):
        resolve_scan_root(f)


@pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics")
def test_resolve_scan_root_follows_symlinks(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    root = resolve_scan_root(link)
    # resolved should point at the real directory.
    assert root.resolved == real.resolve()


def test_resolve_scan_root_extra_ignore_dirs(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path, extra_ignore_dirs=["my_cache"])
    assert "my_cache" in root.ignore_dirs
    # Defaults still included.
    assert "node_modules" in root.ignore_dirs


# --- ResolvedRoot.contains -------------------------------------------------


def test_contains_accepts_descendant(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path)
    sub = tmp_path / "src" / "a.py"
    sub.parent.mkdir(parents=True)
    sub.write_text("x")
    assert root.contains(sub)


def test_contains_rejects_sibling(tmp_path: Path) -> None:
    inside = tmp_path / "project"
    inside.mkdir()
    outside = tmp_path / "other"
    outside.mkdir()
    root = resolve_scan_root(inside)
    assert not root.contains(outside / "x.py")


def test_contains_rejects_parent(tmp_path: Path) -> None:
    inside = tmp_path / "project"
    inside.mkdir()
    root = resolve_scan_root(inside)
    assert not root.contains(tmp_path)  # parent of root


# --- ResolvedRoot.is_ignored -----------------------------------------------


def test_is_ignored_matches_top_level_node_modules(tmp_path: Path) -> None:
    nm = tmp_path / "node_modules" / "pkg" / "index.js"
    nm.parent.mkdir(parents=True)
    nm.write_text("x")
    root = resolve_scan_root(tmp_path)
    assert root.is_ignored(nm)


def test_is_ignored_matches_nested_node_modules(tmp_path: Path) -> None:
    nested = tmp_path / "packages" / "foo" / "node_modules" / "lib" / "x.js"
    nested.parent.mkdir(parents=True)
    nested.write_text("x")
    root = resolve_scan_root(tmp_path)
    assert root.is_ignored(nested)


def test_is_ignored_false_for_regular_source(tmp_path: Path) -> None:
    src = tmp_path / "src" / "main.py"
    src.parent.mkdir()
    src.write_text("x")
    root = resolve_scan_root(tmp_path)
    assert not root.is_ignored(src)


def test_is_ignored_treats_outside_path_as_ignored(tmp_path: Path) -> None:
    inside = tmp_path / "project"
    inside.mkdir()
    outside_file = tmp_path / "x.py"
    outside_file.write_text("x")
    root = resolve_scan_root(inside)
    assert root.is_ignored(outside_file)


# --- ResolvedRoot.relativize -----------------------------------------------


def test_relativize_returns_forward_slash_path(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c.py"
    nested.parent.mkdir(parents=True)
    nested.write_text("x")
    root = resolve_scan_root(tmp_path)
    assert root.relativize(nested) == "a/b/c.py"


def test_relativize_falls_back_for_outside_path(tmp_path: Path) -> None:
    inside = tmp_path / "project"
    inside.mkdir()
    outside = tmp_path / "elsewhere.py"
    outside.write_text("x")
    root = resolve_scan_root(inside)
    # Outside paths fall back to the absolute string; we just confirm we
    # don't crash and get something non-empty.
    s = root.relativize(outside)
    assert s
    assert os.sep not in s or "/" in s  # at least one separator style


# --- DEFAULT_IGNORE_DIRS sanity --------------------------------------------


def test_default_ignore_dirs_includes_well_known() -> None:
    expected = {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}
    assert expected.issubset(DEFAULT_IGNORE_DIRS)


def test_resolved_root_is_immutable() -> None:
    root = ResolvedRoot(original=Path("/x"), resolved=Path("/x"))
    with pytest.raises(FrozenInstanceError):
        root.resolved = Path("/y")  # type: ignore[misc]
