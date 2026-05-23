"""Tests for workspace discovery (Phase 2-B).

We drive the public detection functions directly with a freshly-built
``ResolvedRoot`` over a ``tmp_path``. These tests cover:

- pnpm: packages glob, exclude with ``!``, root-level member, unsafe
  glob rejection, symlinked member rejection.
- npm: array form, ``{packages: [...]}`` Yarn-Classic shape, malformed
  shapes, ``name``-less member rejection.
- uv: workspace stanza detected → warning only, no per-member units
  (Phase 2-B doesn't split uv).
- yarn: ``yarn.lock`` + workspaces → unsupported warning.
- limits: > _WORKSPACE_HARD_CAP truncation, > _WORKSPACE_WARN_THRESHOLD
  warning.
- safety: yaml size limit, ``..`` / absolute / URI-scheme patterns
  rejected before glob expansion.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from secscan.path_safety import resolve_scan_root
from secscan.workspaces import (
    detect_npm_workspace,
    detect_pnpm_workspace,
    detect_uv_workspace,
    detect_yarn_unsupported,
)

# --- pnpm-workspace.yaml -------------------------------------------------


def _write_pnpm_workspace(root: Path, body: str) -> None:
    (root / "pnpm-workspace.yaml").write_text(body, encoding="utf-8")


def _write_package(root: Path, rel: str, name: str) -> Path:
    pkg_dir = root / rel
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": name, "version": "1.0.0"}), encoding="utf-8"
    )
    return pkg_dir


def test_pnpm_workspace_returns_none_when_file_absent(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path)
    assert detect_pnpm_workspace(root) is None


def test_pnpm_workspace_expands_packages_glob(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    _write_package(tmp_path, "packages/api", "@org/api")
    _write_package(tmp_path, "packages/web", "@org/web")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.provider == "pnpm"
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert workspace_ids == {"@org/api", "@org/web"}
    # Every unit's root is the repo root (audit runs from there).
    assert all(u.root == tmp_path.resolve() for u in expansion.units)
    # ecosystem + package_manager populated.
    assert all(u.ecosystem == "npm" for u in expansion.units)
    assert all(u.package_manager == "pnpm" for u in expansion.units)


def test_pnpm_workspace_exclude_patterns(tmp_path: Path) -> None:
    """``!`` prefix marks an exclude pattern."""
    _write_pnpm_workspace(
        tmp_path,
        "packages:\n  - 'packages/*'\n  - '!packages/internal'\n",
    )
    _write_package(tmp_path, "packages/api", "@org/api")
    _write_package(tmp_path, "packages/internal", "@org/internal")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert workspace_ids == {"@org/api"}


def test_pnpm_workspace_lockfile_attached(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    _write_package(tmp_path, "packages/api", "@org/api")
    (tmp_path / "pnpm-lock.yaml").write_text("# pnpm lock\n", encoding="utf-8")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    (unit,) = expansion.units
    assert unit.lockfile is not None
    assert unit.lockfile.name == "pnpm-lock.yaml"


def test_pnpm_workspace_member_without_name_is_skipped(tmp_path: Path) -> None:
    """Members lacking a ``name`` can't be targeted by ``--filter`` and
    are skipped with a warning rather than emitted with no selector."""
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    pkg = tmp_path / "packages" / "unnamed"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"version": "1.0.0"}))
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert any("no 'name'" in w for w in expansion.warnings)


@pytest.mark.skipif(sys.platform == "win32", reason="symlink semantics")
def test_pnpm_workspace_symlinked_member_is_excluded(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'packages/*'\n")
    real_dir = tmp_path / "real_package"
    real_dir.mkdir()
    (real_dir / "package.json").write_text(
        json.dumps({"name": "@org/real"}), encoding="utf-8"
    )
    link = tmp_path / "packages" / "linked"
    link.parent.mkdir()
    link.symlink_to(real_dir, target_is_directory=True)
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert all(u.workspace_id != "@org/real" for u in expansion.units)


@pytest.mark.parametrize(
    "unsafe_pattern",
    [
        "/abs/path",
        "../escape",
        "packages/..",
        "C:\\windows\\path",
        "http://example.com/pkg",
    ],
)
def test_pnpm_workspace_rejects_unsafe_glob_patterns(
    tmp_path: Path, unsafe_pattern: str
) -> None:
    """Unsafe glob patterns are dropped before expansion (Codex 20th)."""
    _write_pnpm_workspace(tmp_path, f"packages:\n  - '{unsafe_pattern}'\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert any("unsafe" in w for w in expansion.warnings)


def test_pnpm_workspace_oversize_file_is_rejected(tmp_path: Path) -> None:
    """A pathologically large pnpm-workspace.yaml is refused before parsing."""
    big = tmp_path / "pnpm-workspace.yaml"
    # 2 MB > 1 MB cap.
    big.write_text("packages:\n  - 'x'\n" + ("# pad\n" * (2 * 1024 * 1024 // 6)))
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    # Returned expansion has no units since _read_yaml refused to parse.
    assert expansion.units == ()


def test_pnpm_workspace_packages_omitted_is_acceptable(tmp_path: Path) -> None:
    """pnpm docs: omitted 'packages:' means root package only."""
    _write_pnpm_workspace(tmp_path, "# nothing here\n")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert expansion.warnings == ()


def test_pnpm_workspace_malformed_yaml_warns(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, ": : : not valid")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()


# --- npm workspaces (array + object forms) -------------------------------


def _write_root_package(root: Path, *, workspaces: object) -> None:
    payload = {"name": "monorepo-root", "private": True, "workspaces": workspaces}
    (root / "package.json").write_text(json.dumps(payload), encoding="utf-8")


def test_npm_workspace_returns_none_when_no_workspaces_key(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    root = resolve_scan_root(tmp_path)
    assert detect_npm_workspace(root) is None


def test_npm_workspace_array_form(tmp_path: Path) -> None:
    _write_root_package(tmp_path, workspaces=["packages/*"])
    _write_package(tmp_path, "packages/api", "@org/api")
    _write_package(tmp_path, "packages/web", "@org/web")
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    workspace_ids = {u.workspace_id for u in expansion.units}
    assert workspace_ids == {"@org/api", "@org/web"}
    assert all(u.package_manager == "npm" for u in expansion.units)


def test_npm_workspace_yarn_classic_object_form(tmp_path: Path) -> None:
    """``{"packages": [...], "nohoist": [...]}`` is accepted; nohoist is ignored."""
    _write_root_package(
        tmp_path,
        workspaces={"packages": ["apps/*"], "nohoist": ["**/foo"]},
    )
    _write_package(tmp_path, "apps/web", "@org/web")
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    (unit,) = expansion.units
    assert unit.workspace_id == "@org/web"


def test_npm_workspace_invalid_shape_warns(tmp_path: Path) -> None:
    _write_root_package(tmp_path, workspaces=42)  # neither array nor object
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert expansion.warnings  # some explanatory warning


def test_npm_workspace_lockfile_attached(tmp_path: Path) -> None:
    _write_root_package(tmp_path, workspaces=["packages/*"])
    _write_package(tmp_path, "packages/api", "@org/api")
    (tmp_path / "package-lock.json").write_text("{}")
    root = resolve_scan_root(tmp_path)
    expansion = detect_npm_workspace(root)
    assert expansion is not None
    (unit,) = expansion.units
    assert unit.lockfile is not None
    assert unit.lockfile.name == "package-lock.json"


# --- uv workspaces -------------------------------------------------------


def test_uv_workspace_detected_but_no_units(tmp_path: Path) -> None:
    """Phase 2-B detects uv workspace stanza but emits a warning instead
    of splitting members (pip-audit can't consume uv.lock directly)."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname='root'\n\n"
        "[tool.uv.workspace]\nmembers = ['packages/*']\n",
        encoding="utf-8",
    )
    root = resolve_scan_root(tmp_path)
    expansion = detect_uv_workspace(root)
    assert expansion is not None
    assert expansion.units == ()
    assert any("uv workspace" in w for w in expansion.warnings)


def test_uv_workspace_returns_none_when_no_stanza(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='root'\n")
    root = resolve_scan_root(tmp_path)
    assert detect_uv_workspace(root) is None


# --- yarn unsupported warning -------------------------------------------


def test_yarn_lock_with_workspaces_warns(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    _write_root_package(tmp_path, workspaces=["packages/*"])
    root = resolve_scan_root(tmp_path)
    warnings = detect_yarn_unsupported(root)
    assert warnings
    assert any("yarn workspaces" in w for w in warnings)


def test_yarn_lock_with_other_lockfile_emits_drift_warning(
    tmp_path: Path,
) -> None:
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    root = resolve_scan_root(tmp_path)
    warnings = detect_yarn_unsupported(root)
    assert any("drift" in w for w in warnings)


def test_yarn_lock_alone_no_workspaces_no_warning(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    root = resolve_scan_root(tmp_path)
    assert detect_yarn_unsupported(root) == ()


# --- workspace count limits ---------------------------------------------


def test_workspace_warn_threshold(tmp_path: Path) -> None:
    """Exceeding the warn threshold triggers a non-fatal advisory."""
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'pkg/*'\n")
    # 55 members > the 50 warn threshold.
    for i in range(55):
        _write_package(tmp_path, f"pkg/p{i:03d}", f"@org/p{i:03d}")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert len(expansion.units) == 55
    assert any("may take a while" in w for w in expansion.warnings)


def test_workspace_hard_cap_truncates(tmp_path: Path) -> None:
    _write_pnpm_workspace(tmp_path, "packages:\n  - 'pkg/*'\n")
    # 120 members > the 100 hard cap.
    for i in range(120):
        _write_package(tmp_path, f"pkg/p{i:03d}", f"@org/p{i:03d}")
    root = resolve_scan_root(tmp_path)
    expansion = detect_pnpm_workspace(root)
    assert expansion is not None
    assert len(expansion.units) == 100
    assert any("truncating" in w for w in expansion.warnings)
