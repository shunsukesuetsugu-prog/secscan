"""Dependency-CVE scanner (orchestrator-facing).

This class is the dispatch layer over the per-tool adapters in
``scanners/deps/``. ``is_applicable`` filters WorkUnits down to those with
an ecosystem we support; ``scan`` selects the adapter based on
``WorkUnit.package_manager`` and runs the corresponding external tool.

The scanner enforces lockfile policy locally:
- ecosystems where a lockfile is mandatory (npm, pnpm) fail with a
  scanner-level error when none is present unless ``allow_missing_lockfile``
  is True in ScanConfig.extra.
- pip-audit handles a missing lockfile more gracefully via ``--strict``,
  but we surface a warning so the user knows the result is less precise.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from ..models import (
    Finding,
    ScanConfig,
    ScannerError,
    ScanOutcome,
    WorkUnit,
)
from ..redact import redact_text, truncate
from ..runner import CommandResult, CommandRunner, decode_output
from .base import Scanner, ToolNotFoundError
from .deps.npm import (
    build_findings_from_npm_audit,
    classify_npm_audit_exit,
    npm_audit_argv,
)
from .deps.pip_audit import (
    build_findings_from_pip_audit,
    classify_pip_audit_exit,
    pip_audit_argv_for_project,
    pip_audit_argv_for_requirements,
)
from .deps.pnpm import (
    build_findings_from_pnpm_audit,
    classify_pnpm_audit_exit,
    pnpm_audit_argv,
)
from .deps.yarn import (
    build_findings_from_yarn_audit,
    classify_yarn_audit_exit,
    yarn_audit_argv,
)

_Classifier = Callable[[CommandResult], tuple[bool, str | None]]
_Builder = Callable[[bytes], tuple[Finding, ...]]

_SUPPORTED_ECOSYSTEMS = frozenset({"npm", "pypi"})

# Which package managers require a lockfile to produce meaningful output.
# Without one, ``allow_missing_lockfile`` must be True or we error out.
_PMS_REQUIRING_LOCKFILE = frozenset({"npm", "pnpm"})


class DepsScanner(Scanner):
    name: ClassVar[str] = "deps"
    # The "tool" varies per WorkUnit; we keep these for the Scanner contract
    # but actual executable checks happen per-adapter below.
    tool_executable: ClassVar[str] = "deps (npm/pnpm/pip-audit)"
    install_hint: ClassVar[str] = (
        "install the relevant package manager(s): npm v7+, pnpm v8+, "
        "and/or pip-audit (`pip install pip-audit` or `secscan[deps]`)"
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        return unit.ecosystem in _SUPPORTED_ECOSYSTEMS

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        package_manager = unit.package_manager
        if package_manager is None:
            return _make_error(
                "deps scanner received a WorkUnit without a package_manager"
            )

        allow_missing = bool(config.extra.get("allow_missing_lockfile", False))
        omit_dev = bool(config.extra.get("ignore_dev_dependencies", False))

        if package_manager == "npm":
            return self._run_npm_like(
                unit=unit,
                runner=runner,
                config=config,
                argv=npm_audit_argv(
                    allow_missing_lockfile=allow_missing,
                    omit_dev=omit_dev,
                    workspace_id=unit.workspace_id,
                ),
                tool="npm",
                allow_missing_lockfile=allow_missing,
                classifier=classify_npm_audit_exit,
                builder=lambda stdout: build_findings_from_npm_audit(
                    stdout, workspace_id=unit.workspace_id
                ),
            )
        if package_manager == "pnpm":
            return self._run_npm_like(
                unit=unit,
                runner=runner,
                config=config,
                argv=pnpm_audit_argv(
                    omit_dev=omit_dev, workspace_id=unit.workspace_id
                ),
                tool="pnpm",
                allow_missing_lockfile=allow_missing,
                classifier=classify_pnpm_audit_exit,
                builder=lambda stdout: build_findings_from_pnpm_audit(
                    stdout, workspace_id=unit.workspace_id
                ),
            )
        if package_manager == "yarn":
            if unit.workspace_id is None:
                return _make_error(
                    "yarn deps audit requires a workspace selector but the "
                    "WorkUnit had none; this is an internal discovery bug.",
                    returncode=None,
                )
            return self._run_npm_like(
                unit=unit,
                runner=runner,
                config=config,
                argv=yarn_audit_argv(workspace_id=unit.workspace_id),
                tool="yarn",
                allow_missing_lockfile=False,  # yarn.lock is required for audit
                classifier=classify_yarn_audit_exit,
                builder=lambda stdout: build_findings_from_yarn_audit(
                    stdout, workspace_id=unit.workspace_id or ""
                ),
            )
        if package_manager in {"pip", "uv", "pdm", "pip-requirements"}:
            return self._run_pip_audit(unit=unit, runner=runner, config=config)

        return _make_error(
            f"deps scanner does not know how to handle package_manager={package_manager!r}"
        )

    # --- npm / pnpm path ---------------------------------------------------

    def _run_npm_like(
        self,
        *,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
        argv: tuple[str, ...],
        tool: str,
        allow_missing_lockfile: bool,
        classifier: _Classifier,
        builder: _Builder,
    ) -> ScanOutcome:
        if shutil.which(tool) is None:
            raise ToolNotFoundError(
                tool,
                f"install {tool} (e.g. via Node.js's package manager) and ensure it is on PATH",
            )

        if (
            unit.lockfile is None
            and tool in _PMS_REQUIRING_LOCKFILE
            and not allow_missing_lockfile
        ):
            return _make_error(
                f"{tool} requires a lockfile to produce a meaningful audit; "
                f"none found under {unit.root}. Use --allow-missing-lockfile to scan anyway.",
                returncode=None,
            )

        result = runner.run(
            argv,
            cwd=unit.root,
            timeout_seconds=config.timeout_seconds,
        )
        ok, error_reason = classifier(result)
        if not ok:
            return _make_error(
                error_reason or f"{tool} audit failed",
                stderr=result.stderr,
                returncode=result.returncode,
                duration=result.duration_seconds,
            )
        findings = builder(result.stdout)
        return ScanOutcome(
            scanner=self.name,
            findings=findings,
            tool_version=None,  # Phase 1C: probe per-tool version
            duration_seconds=result.duration_seconds,
        )

    # --- pip-audit path ----------------------------------------------------

    def _run_pip_audit(
        self,
        *,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        if shutil.which("pip-audit") is None:
            raise ToolNotFoundError(
                "pip-audit",
                "install pip-audit (`pip install pip-audit` or "
                "`pip install 'secscan[deps]'`) and ensure it is on PATH",
            )

        # Phase 2-C-1: when this is a uv workspace member, go through
        # ``uv export --package <name>`` to produce a per-member
        # requirements.txt and audit that. The legacy single-project
        # paths still dispatch to ``_select_pip_audit_argv``.
        if unit.package_manager == "uv" and unit.workspace_id is not None:
            return self._run_uv_workspace_audit(
                unit=unit, runner=runner, config=config
            )

        argv = self._select_pip_audit_argv(unit)
        if isinstance(argv, ScanOutcome):
            return argv  # An error result returned for unsupported input.

        result = runner.run(
            argv,
            cwd=unit.root,
            timeout_seconds=config.timeout_seconds,
        )
        ok, error_reason = classify_pip_audit_exit(result)
        if not ok:
            return _make_error(
                error_reason or "pip-audit failed",
                stderr=result.stderr,
                returncode=result.returncode,
                duration=result.duration_seconds,
            )
        findings = build_findings_from_pip_audit(result.stdout)
        return ScanOutcome(
            scanner=self.name,
            findings=findings,
            tool_version=None,
            duration_seconds=result.duration_seconds,
        )

    def _run_uv_workspace_audit(
        self,
        *,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        """uv workspace member audit via ``uv export`` + ``pip-audit``.

        Two subprocess calls:

        1. ``uv export --locked --format requirements.txt --output-file
           <tmp> --package <name> --no-hashes --no-emit-local``
           - ``--locked`` refuses to re-lock; we must NOT mutate the
             user's uv.lock during a scan (Codex 23rd review).
           - ``--no-emit-local`` keeps first-party workspace packages
             out of the requirements file, eliminating a class of
             pip-audit false positives and local-path resolution.
           - The output file lives in a 0700 temp dir created with
             ``tempfile.mkdtemp`` so the requirements (which may
             contain index URLs etc.) are not world-readable.

        2. ``pip-audit --format json --strict --requirement <tmp>``
           as the existing requirements path. Findings inherit the
           ``workspace_id`` so they carry a distinct ``deps-ws:`` fingerprint.
        """
        if shutil.which("uv") is None:
            raise ToolNotFoundError(
                "uv",
                "install uv (`pip install uv` or `brew install uv`) and "
                "ensure it is on PATH",
            )

        # 0700 dir + 0600 file. Codex 23rd review: don't put the
        # requirements file under the scan root — keep secrets in
        # index URLs etc. from leaking into ignored-but-readable
        # locations.
        tmp_dir = Path(tempfile.mkdtemp(prefix="secscan-uv-"))
        os.chmod(tmp_dir, 0o700)
        tmp_file = tmp_dir / "requirements.txt"
        try:
            tmp_file.touch(mode=0o600, exist_ok=False)
            export_argv = (
                "uv",
                "export",
                "--locked",
                "--format",
                "requirements.txt",
                "--output-file",
                str(tmp_file),
                "--package",
                unit.workspace_id or "",
                "--no-hashes",
                "--no-emit-local",
            )
            export_result = runner.run(
                export_argv,
                cwd=unit.root,
                timeout_seconds=config.timeout_seconds,
            )
            if export_result.timed_out or export_result.returncode != 0:
                return _make_error(
                    f"uv export failed for workspace member "
                    f"'{unit.workspace_id}'"
                    + (" (timed out)" if export_result.timed_out else ""),
                    stderr=export_result.stderr,
                    returncode=export_result.returncode,
                    duration=export_result.duration_seconds,
                )
            audit_argv = pip_audit_argv_for_requirements(str(tmp_file))
            result = runner.run(
                audit_argv,
                cwd=unit.root,
                timeout_seconds=config.timeout_seconds,
            )
            ok, error_reason = classify_pip_audit_exit(result)
            if not ok:
                return _make_error(
                    error_reason or "pip-audit failed",
                    stderr=result.stderr,
                    returncode=result.returncode,
                    duration=result.duration_seconds,
                )
            findings = build_findings_from_pip_audit(
                result.stdout, workspace_id=unit.workspace_id
            )
            return ScanOutcome(
                scanner=self.name,
                findings=findings,
                tool_version=None,
                duration_seconds=result.duration_seconds
                + export_result.duration_seconds,
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _select_pip_audit_argv(
        self, unit: WorkUnit
    ) -> tuple[str, ...] | ScanOutcome:
        """Pick the right pip-audit invocation for this WorkUnit.

        Modes (Codex 8th review):
        - requirements.txt / pylock.toml  →  ``-r <file>``
        - pyproject.toml + no lock         →  ``<project-path>``
                                              (audits the project, NOT the
                                              current Python env — see
                                              pip_audit.py docstring).
        - uv.lock / pdm.lock               →  ScanError: pip-audit cannot
                                              consume these directly; the
                                              user must export to
                                              requirements.txt first.
        - setup.py only                    →  project-path mode.
        """
        # Lockfile dictates the mode when present.
        if unit.lockfile is not None:
            lock_name = unit.lockfile.name
            if lock_name == "pylock.toml" or lock_name.endswith(".txt"):
                return pip_audit_argv_for_requirements(str(unit.lockfile))
            if lock_name in ("uv.lock", "pdm.lock"):
                return _make_error(
                    f"pip-audit does not consume {lock_name} directly. "
                    f"Export to requirements.txt first "
                    f"(`uv export -o requirements.txt` or "
                    f"`pdm export -o requirements.txt`) and re-run.",
                    returncode=None,
                )
            # Unknown lockfile name: be conservative — error out rather
            # than guess.
            return _make_error(
                f"unrecognized Python lockfile: {lock_name}. "
                f"Supported: pylock.toml, requirements*.txt.",
                returncode=None,
            )

        # No lockfile. requirements.txt-style manifests also live under
        # ``manifest`` in this branch (set by discovery._detect_pypi).
        if unit.manifest is not None and unit.manifest.name.endswith(".txt"):
            return pip_audit_argv_for_requirements(str(unit.manifest))

        # pyproject-only / setup.py-only → project-path mode.
        return pip_audit_argv_for_project(str(unit.root))


# --- Helpers ---------------------------------------------------------------


def _make_error(
    reason: str,
    *,
    stderr: bytes = b"",
    returncode: int | None = None,
    duration: float = 0.0,
) -> ScanOutcome:
    """Build a ScanOutcome carrying a redacted, length-bounded error."""
    excerpt: str | None = None
    if stderr:
        excerpt = truncate(redact_text(decode_output(stderr)))
        if not excerpt:
            excerpt = None
    safe_reason = truncate(redact_text(reason), limit=300)
    return ScanOutcome(
        scanner="deps",
        error=ScannerError(
            scanner="deps",
            reason=safe_reason,
            stderr_excerpt=excerpt,
            returncode=returncode,
        ),
        duration_seconds=duration,
    )
