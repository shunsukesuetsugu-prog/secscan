"""Tests for project discovery.

Covers:
- Non-deps scanners get a single root WorkUnit.
- npm/pnpm: detects package.json, picks the right lockfile by priority.
- pypi: detects pyproject / requirements / setup.py.
- Both ecosystems coexist (Web + Python in same repo).
- No manifests → warning.
- Nested manifests → warning, but they are NOT scanned.
- Symlinks and ignored dirs do not contribute to nested-warning noise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secscan.discovery import discover_for_scanner
from secscan.path_safety import resolve_scan_root

# --- Non-deps scanners -----------------------------------------------------


def test_secrets_returns_single_root_work_unit(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("secrets", root)
    assert len(discovery.work_units) == 1
    assert discovery.work_units[0].root == root.resolved
    assert discovery.work_units[0].ecosystem is None
    assert discovery.warnings == ()


def test_sast_returns_single_root_work_unit(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("sast", root)
    assert len(discovery.work_units) == 1
    assert discovery.work_units[0].ecosystem is None


# --- deps: npm -------------------------------------------------------------


def test_deps_detects_npm_with_package_lock(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    npms = [w for w in discovery.work_units if w.ecosystem == "npm"]
    assert len(npms) == 1
    assert npms[0].lockfile == (tmp_path / "package-lock.json").resolve()
    assert npms[0].package_manager == "npm"


def test_deps_prefers_pnpm_lockfile_over_npm(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "pnpm-lock.yaml").write_text("")
    root = resolve_scan_root(tmp_path)
    (npm,) = [w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "npm"]
    assert npm.lockfile is not None
    assert npm.lockfile.name == "pnpm-lock.yaml"
    # CRITICAL: the package_manager must follow the lockfile, not stay "npm".
    # pnpm has different --audit-level semantics than npm and the adapter
    # picks the CLI by package_manager.
    assert npm.package_manager == "pnpm"


def test_deps_npm_without_lockfile_defaults_to_npm(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    root = resolve_scan_root(tmp_path)
    (npm,) = [w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "npm"]
    assert npm.lockfile is None
    assert npm.package_manager == "npm"


# --- deps: pypi ------------------------------------------------------------


def test_deps_detects_pypi_pyproject_with_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "uv.lock").write_text("")
    root = resolve_scan_root(tmp_path)
    (pypi,) = [w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "pypi"]
    assert pypi.manifest is not None
    assert pypi.manifest.name == "pyproject.toml"
    assert pypi.lockfile is not None
    assert pypi.lockfile.name == "uv.lock"
    assert pypi.package_manager == "uv"


def test_deps_detects_pypi_pyproject_with_pdm_lock(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "pdm.lock").write_text("")
    root = resolve_scan_root(tmp_path)
    (pypi,) = [w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "pypi"]
    assert pypi.package_manager == "pdm"


def test_deps_detects_pypi_requirements_txt(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==1.0")
    root = resolve_scan_root(tmp_path)
    (pypi,) = [w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "pypi"]
    assert pypi.manifest is not None
    assert pypi.manifest.name == "requirements.txt"
    # requirements.txt is its own "lock-ish" file in MVP.
    assert pypi.lockfile == pypi.manifest
    assert pypi.package_manager == "pip-requirements"


def test_deps_detects_pypi_setup_py_only(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("from setuptools import setup; setup()")
    root = resolve_scan_root(tmp_path)
    (pypi,) = [w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "pypi"]
    assert pypi.manifest is not None
    assert pypi.manifest.name == "setup.py"
    assert pypi.lockfile is None
    assert pypi.package_manager == "pip"


def test_deps_detects_pypi_non_canonical_requirements_only(tmp_path: Path) -> None:
    (tmp_path / "requirements-dev.txt").write_text("pytest")
    root = resolve_scan_root(tmp_path)
    (pypi,) = [w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "pypi"]
    assert pypi.manifest is not None
    # Picks the lexicographically-first match deterministically.
    assert pypi.manifest.name.startswith("requirements")


# --- deps: combined --------------------------------------------------------


def test_deps_emits_both_ecosystems_when_present(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    ecosystems = {w.ecosystem for w in discovery.work_units}
    assert ecosystems == {"npm", "pypi"}


# --- deps: warnings --------------------------------------------------------


def test_deps_warns_when_no_manifest(tmp_path: Path) -> None:
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    assert discovery.work_units == ()
    assert any("no dependency manifest" in w for w in discovery.warnings)


def test_deps_warns_about_nested_manifests(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    nested = tmp_path / "packages" / "inner"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text("{}")
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    assert any("nested package manifests" in w for w in discovery.warnings)
    # The nested one is reported but NOT scanned.
    assert all(w.root == tmp_path.resolve() for w in discovery.work_units)


def test_nested_manifests_ignore_node_modules(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    nm = tmp_path / "node_modules" / "lodash"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text("{}")
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    # node_modules manifests must NOT appear in nested warnings.
    assert all("node_modules" not in w for w in discovery.warnings)


def test_top_level_manifest_symlink_is_ignored(tmp_path: Path) -> None:
    """Codex 8th review: a symlinked manifest at the scan root could point
    outside the root, letting the package manager read out-of-tree files.
    Discovery must reject symlinked manifests outright."""
    # Create the real file outside the scan root and symlink to it.
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    real_pkg_json = outside_root / "package.json"
    real_pkg_json.write_text("{}")

    scan_root_dir = tmp_path / "project"
    scan_root_dir.mkdir()
    link = scan_root_dir / "package.json"
    try:
        link.symlink_to(real_pkg_json)
    except OSError:
        pytest.skip("symlinks not supported on this platform")
    root = resolve_scan_root(scan_root_dir)
    discovery = discover_for_scanner("deps", root)
    # No WorkUnit emitted; user sees a "no manifest" warning instead.
    assert not [w for w in discovery.work_units if w.ecosystem == "npm"]


def test_top_level_lockfile_symlink_is_ignored(tmp_path: Path) -> None:
    scan_root_dir = tmp_path / "project"
    scan_root_dir.mkdir()
    (scan_root_dir / "package.json").write_text("{}")
    # Real lockfile lives outside the scan root.
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    real_lock = outside / "package-lock.json"
    real_lock.write_text("{}")
    link = scan_root_dir / "package-lock.json"
    try:
        link.symlink_to(real_lock)
    except OSError:
        pytest.skip("symlinks not supported on this platform")
    root = resolve_scan_root(scan_root_dir)
    (npm,) = [
        w for w in discover_for_scanner("deps", root).work_units if w.ecosystem == "npm"
    ]
    # Lockfile must be None — the symlink was rejected. The Scanner will
    # then either error out (default) or proceed with --no-package-lock.
    assert npm.lockfile is None


def test_pnpm_workspace_empty_falls_back_to_root_scan(tmp_path: Path) -> None:
    """Codex 21st review BLOCKER: an empty/comments-only
    pnpm-workspace.yaml must NOT silently disable the single-project
    deps scan at the repo root. ``pnpm.units == ()`` is OK; the regular
    npm/pnpm root detection should still produce one WorkUnit."""
    (tmp_path / "pnpm-workspace.yaml").write_text("# nothing here\n")
    (tmp_path / "package.json").write_text("{\"name\": \"root\"}")
    (tmp_path / "package-lock.json").write_text("{}")
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    npm_units = [w for w in discovery.work_units if w.ecosystem == "npm"]
    assert len(npm_units) == 1
    # Root scan is still emitted with no workspace_id.
    assert npm_units[0].workspace_id is None


def test_yarn_unsupported_blocks_npm_workspace_processing(
    tmp_path: Path,
) -> None:
    """Codex 21st review: a yarn-only repo with package.json#workspaces
    must NOT then be processed as an npm workspace. Otherwise we'd run
    ``npm audit --workspace <id>`` on a project that lacks the npm
    lockfile, producing a confusing error."""
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    (tmp_path / "package.json").write_text(
        '{"name": "root", "workspaces": ["packages/*"]}'
    )
    pkg = tmp_path / "packages" / "api"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text('{"name": "@org/api"}')
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    # No workspace_id-bearing units (npm workspace expansion was skipped).
    assert all(
        w.workspace_id is None
        for w in discovery.work_units
        if w.ecosystem == "npm"
    )
    # The unsupported warning is surfaced.
    assert any("yarn workspaces" in w for w in discovery.warnings)


def test_nested_manifests_skip_symlinks(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "package.json").write_text("{}")
    link = tmp_path / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not supported on this platform")
    root = resolve_scan_root(tmp_path)
    discovery = discover_for_scanner("deps", root)
    # The symlinked path should not appear in nested manifests.
    assert all("linked" not in w for w in discovery.warnings)
