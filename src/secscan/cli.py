"""Command-line entry point.

Argument parsing, config resolution, scanner registration, output, exit. The
CLI is intentionally thin: anything testable lives in orchestrator / policy
/ reporter / baseline.

Subcommand structure (Phase 1A — Phase 1B/1C will register additional
scanners but the CLI shape does not change):

    secscan secrets   [options]
    secscan deps      [options]      # Phase 1B
    secscan sast      [options]      # Phase 1C
    secscan all       [options]      # Phase 1D
    secscan baseline  accept|list|prune

Exit codes follow ``exit_codes.ExitCode``. SIGINT yields 130 (POSIX).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from . import __version__
from .baseline import (
    BaselineError,
    build_entries_for_accept,
    is_ci_environment,
    load_baseline,
    merge_entries,
    prune_expired,
    save_baseline,
)
from .config import ConfigError, ProjectConfig, load_config
from .exit_codes import ExitCode
from .formatters import FormatOptions, format_for
from .formatters.base import known_format_names
from .models import Severity
from .orchestrator import run_scanners
from .path_safety import PathSafetyError, resolve_scan_root
from .runner import SubprocessCommandRunner
from .scanners.base import Scanner
from .scanners.config_scanner import ConfigScanner
from .scanners.dast import DastScanner
from .scanners.deps_scanner import DepsScanner
from .scanners.sast import SastScanner
from .scanners.secrets import SecretsScanner

# Registry of scanners available in this build.
ALL_SCANNERS: list[type[Scanner]] = [
    SecretsScanner,
    DepsScanner,
    SastScanner,
    DastScanner,
    ConfigScanner,
]
"""Currently-implemented Scanner classes.

When a subcommand maps to a scanner NOT in this list (e.g. ``secscan deps``
in Phase 1A), the CLI must NOT silently run zero scanners — that would let
CI report ``deps`` as clean when it was never actually checked. ``_dispatch``
explicitly rejects subcommands without a corresponding registered scanner.
"""

_REGISTERED_NAMES: set[str] = {cls.name for cls in ALL_SCANNERS}


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns an integer exit code instead of calling sys.exit
    so tests can drive the CLI without process teardown."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        return int(ExitCode.INTERRUPTED)


# --- Parser ----------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Cross-project vulnerability scanning (deps / sast / secrets).",
    )
    parser.add_argument("--version", action="version", version=f"secscan {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # secscan secrets / deps / sast / dast / config / all — share flags.
    for cmd in ("secrets", "deps", "sast", "dast", "config", "all"):
        sub = subparsers.add_parser(cmd, help=f"run the {cmd} scanner")
        _add_common_scan_args(sub)
        if cmd == "all":
            sub.add_argument(
                "--skip",
                action="append",
                default=[],
                metavar="SCANNER",
                help=(
                    "scanner to skip (repeatable). Choices: secrets, deps, "
                    "sast, dast, config."
                ),
            )
        if cmd == "config":
            sub.add_argument(
                "--trivy-image",
                default=None,
                metavar="IMAGE",
                help=(
                    "OCI image reference (digest-pinned) for the Trivy "
                    "config scanner. Format: '<repo>[:tag]@sha256:<64 hex>'."
                ),
            )
        if cmd == "sast":
            sub.add_argument(
                "--semgrep-config",
                action="append",
                default=None,
                metavar="RULESET",
                help="override semgrep --config (repeatable).",
            )
        if cmd == "deps":
            sub.add_argument(
                "--allow-missing-lockfile",
                action="store_true",
                help="proceed even when a project has no lockfile.",
            )
        if cmd == "dast":
            sub.add_argument(
                "--target",
                required=True,
                metavar="URL",
                help="DAST target URL (http:// or https://). Required.",
            )
            sub.add_argument(
                "--zap-image",
                default=None,
                metavar="IMAGE",
                help=(
                    "OCI image reference (digest-pinned) for the OWASP ZAP "
                    "container. Format: '<repo>[:tag]@sha256:<64 hex>'."
                ),
            )
            sub.add_argument(
                "--ajax-spider",
                action="store_true",
                help="enable ZAP's AJAX spider (slower; needed for JS-heavy sites).",
            )
            sub.add_argument(
                "--zap-config-file",
                default=None,
                metavar="PATH",
                help=(
                    "ZAP context file path INSIDE the container. The operator "
                    "is responsible for mounting it (secscan does not add -v)."
                ),
            )
            sub.add_argument(
                "--zap-network",
                choices=("bridge", "host"),
                default=None,
                help=(
                    "docker --network mode (default: bridge). Use 'host' only "
                    "when the target is reachable only on the host namespace."
                ),
            )
            sub.add_argument(
                "--mode",
                choices=("baseline", "active"),
                default=None,
                help=(
                    "ZAP scan mode (default: baseline). 'active' runs "
                    "zap-full-scan.py which sends payloads (SQLi / XSS / "
                    "auth-bypass) — 10x slower and DO NOT point at "
                    "production targets."
                ),
            )

    # secscan baseline …
    baseline_parser = subparsers.add_parser(
        "baseline", help="manage the baseline (known-issue suppression file)"
    )
    bl_sub = baseline_parser.add_subparsers(dest="baseline_command", required=True)

    accept = bl_sub.add_parser("accept", help="record findings as accepted")
    accept.add_argument("--path", default=".", help="scan root (default: cwd)")
    accept.add_argument(
        "--fingerprint",
        action="append",
        default=[],
        metavar="HASH",
        help="fingerprint to accept (repeatable). Required unless --all is given.",
    )
    accept.add_argument(
        "--all",
        dest="accept_all",
        action="store_true",
        help="accept EVERY current finding. Use with care.",
    )
    accept.add_argument(
        "--reason",
        required=True,
        help="non-empty justification recorded with each entry.",
    )
    accept.add_argument(
        "--expiry-days",
        type=int,
        default=None,
        help="override config's default_expiry_days for the new entries.",
    )

    bl_list = bl_sub.add_parser("list", help="show baseline entries")
    bl_list.add_argument("--path", default=".", help="scan root (default: cwd)")

    bl_prune = bl_sub.add_parser("prune", help="remove expired baseline entries")
    bl_prune.add_argument("--path", default=".", help="scan root (default: cwd)")

    return parser


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", default=".", help="scan root (default: cwd)")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default=None,
        help="severity threshold for non-zero exit (default: from config; high)",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="ignore any baseline file for this run.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors even on a TTY.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="emit a single-line summary instead of the full report.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show suppressed findings and extended metadata.",
    )
    parser.add_argument(
        "--format",
        choices=sorted(known_format_names()),
        default="text",
        help="output format (default: text). json/sarif are mutually exclusive with --quiet.",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="write the formatted report to FILE instead of stdout.",
    )
    parser.add_argument(
        "--sarif-include-suppressed",
        action="store_true",
        help=(
            "include baseline-suppressed findings in SARIF output (default: "
            "excluded; GitHub Code Scanning does not consistently honor "
            "SARIF suppressions)."
        ),
    )


# --- Dispatch --------------------------------------------------------------


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "baseline":
        return _dispatch_baseline(args)
    return _dispatch_scan(args)


def _dispatch_scan(args: argparse.Namespace) -> int:
    # Codex 18th review: validate format/quiet incompatibility BEFORE we
    # start any scanner. The previous order ran gitleaks / npm /
    # pip-audit / semgrep and only then noticed the CLI was invalid.
    format_name = getattr(args, "format", "text")
    if getattr(args, "quiet", False) and format_name != "text":
        _print_error(
            f"--quiet is only valid with --format=text; got --format={format_name}"
        )
        return int(ExitCode.SCAN_ERROR)

    try:
        scan_root = resolve_scan_root(args.path)
    except PathSafetyError as exc:
        _print_error(f"path error: {exc}")
        return int(ExitCode.SCAN_ERROR)

    try:
        config = load_config(scan_root.resolved)
    except ConfigError as exc:
        _print_error(f"config error: {exc}")
        return int(ExitCode.SCAN_ERROR)

    config = _apply_cli_overrides(config, args)

    only: tuple[str, ...] | None = None if args.command == "all" else (args.command,)

    # CRITICAL: refuse to run a scanner-specific subcommand if its scanner
    # isn't registered in this build. Otherwise the user would see
    # "no findings, exit 0" for a scanner that never actually ran — a false
    # green that defeats the whole point of a security gate.
    if only is not None and only[0] not in _REGISTERED_NAMES:
        _print_error(
            f"the {only[0]!r} scanner is declared but not yet implemented in this "
            f"build of secscan. Registered scanners: {sorted(_REGISTERED_NAMES)}"
        )
        return int(ExitCode.SCAN_ERROR)

    # For ``secscan all``, the user expects "every kind of check we know
    # about" — secrets + deps + sast. DAST is intentionally NOT in this
    # set: it's opt-in (per-deployment) and only runs when ``--target``
    # is configured. If any non-DAST scanner is NOT registered, warn
    # (and skip-list it) instead of silently running a subset and
    # exiting 0. Explicitly skipped scanners (--skip / config.skip)
    # do NOT count as "missing" — the user already acknowledged that gap.
    expected_all_scanners = {"secrets", "deps", "sast"}
    missing_for_all: tuple[str, ...] = ()
    if args.command == "all":
        user_skipped = set(config.skip) | set(getattr(args, "skip", ()) or ())
        missing_for_all = tuple(
            sorted(expected_all_scanners - _REGISTERED_NAMES - user_skipped)
        )

    # DAST runs only when a target is configured. For ``secscan dast``,
    # the CLI flag is required (argparse enforces that). For ``secscan all``,
    # DAST is excluded unless ``dast.target`` was set in config. We achieve
    # this by filtering DastScanner OUT of the registered instances when
    # the resolved config has no target.
    scanners = _build_scanner_instances(config, command=args.command)

    runner = SubprocessCommandRunner()
    try:
        outcome = run_scanners(
            scanners,
            scan_root=scan_root,
            config=config,
            runner=runner,
            only=only,
        )
    except BaselineError as exc:
        # We surface baseline errors at this level (parse failures during
        # apply, etc.) — never silently ignore them.
        _print_error(f"baseline error: {exc}")
        return int(ExitCode.SCAN_ERROR)

    final_result = outcome.result
    if missing_for_all:
        # Augment the RunResult so the reporter shows these as gaps. Frozen
        # dataclass — replace, don't mutate.
        from dataclasses import replace as _replace

        final_result = _replace(
            final_result,
            skipped=tuple(sorted(set(final_result.skipped) | set(missing_for_all))),
            warnings=(
                *final_result.warnings,
                f"`secscan all` ran a partial scan: the following scanner(s) are not "
                f"yet implemented in this build and were SKIPPED, not passed: "
                f"{', '.join(missing_for_all)}",
            ),
        )

    # When ``all`` is partial, we must not exit 0 on findings==0. The user
    # asked for "everything" and got "subset"; that's an inconclusive scan
    # for CI purposes, not a clean one.
    if missing_for_all and outcome.decision.exit_code == ExitCode.OK:
        from dataclasses import replace as _replace

        final_decision = _replace(outcome.decision, exit_code=ExitCode.SCAN_ERROR)
    else:
        final_decision = outcome.decision

    # format_name / quiet were already validated at the top of this
    # function before scanners ran (Codex 18th review).
    quiet = getattr(args, "quiet", False)

    options = FormatOptions(
        use_color=_should_use_color(args, sys.stdout) and format_name == "text",
        verbose=getattr(args, "verbose", False),
        quiet=quiet,
        include_suppressed_in_sarif=getattr(
            args, "sarif_include_suppressed", False
        ),
    )
    rendered = format_for(format_name)(final_result, final_decision, options)

    output_path = getattr(args, "output", None)
    if output_path is None:
        sys.stdout.write(rendered)
        # Preserve the historical trailing newline for text-format stdout;
        # json/sarif formatters already terminate with a newline themselves.
        if format_name == "text" and not rendered.endswith("\n"):
            sys.stdout.write("\n")
    else:
        try:
            Path(output_path).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            _print_error(f"could not write --output {output_path}: {exc}")
            return int(ExitCode.SCAN_ERROR)
    return int(final_decision.exit_code)


def _dispatch_baseline(args: argparse.Namespace) -> int:
    try:
        scan_root = resolve_scan_root(args.path)
    except PathSafetyError as exc:
        _print_error(f"path error: {exc}")
        return int(ExitCode.SCAN_ERROR)

    try:
        config = load_config(scan_root.resolved)
    except ConfigError as exc:
        _print_error(f"config error: {exc}")
        return int(ExitCode.SCAN_ERROR)

    try:
        if args.baseline_command == "accept":
            return _baseline_accept(args, scan_root.resolved, config)
        if args.baseline_command == "list":
            return _baseline_list(config)
        if args.baseline_command == "prune":
            return _baseline_prune(config)
        _print_error(f"unknown baseline command: {args.baseline_command}")
        return int(ExitCode.SCAN_ERROR)
    except BaselineError as exc:
        _print_error(f"baseline error: {exc}")
        return int(ExitCode.SCAN_ERROR)


def _baseline_accept(
    args: argparse.Namespace, scan_root: Path, config: ProjectConfig
) -> int:
    if is_ci_environment():
        _print_error(
            "refusing to write baseline in CI environment (SECSCAN_CI=1). "
            "Accept findings locally and commit the baseline file instead."
        )
        return int(ExitCode.SCAN_ERROR)

    if not args.fingerprint and not args.accept_all:
        _print_error("must specify --fingerprint <hash> ... or --all")
        return int(ExitCode.SCAN_ERROR)

    if not args.reason.strip():
        _print_error("--reason must not be empty")
        return int(ExitCode.SCAN_ERROR)

    # Re-run scanners on the scan root to discover current fingerprints.
    # DAST is filtered out unless explicitly configured: baseline accept
    # only re-runs the static analysis scanners (Codex 17th-style
    # safeguard — a missing DAST target must not crash baseline accept).
    scanners = _build_scanner_instances(config, command="baseline")
    runner = SubprocessCommandRunner()
    outcome = run_scanners(
        scanners,
        scan_root=resolve_scan_root(str(scan_root)),
        config=config,
        runner=runner,
    )

    # Codex 12th review: refusing to accept when the scan was inconclusive
    # prevents users from locking in a baseline that's missing real findings
    # because one of the scanners errored out.
    if outcome.result.errors:
        scanners_in_error = ", ".join(
            sorted({e.scanner for e in outcome.result.errors})
        )
        _print_error(
            f"refusing to accept findings: one or more scanners failed "
            f"({scanners_in_error}). Resolve the scanner error(s) first so "
            f"the baseline reflects a complete scan."
        )
        return int(ExitCode.SCAN_ERROR)

    candidates = outcome.result.findings
    if args.accept_all:
        selected = candidates
    else:
        wanted = set(args.fingerprint)
        selected = tuple(f for f in candidates if f.fingerprint in wanted)
        unknown = wanted - {f.fingerprint for f in candidates}
        if unknown:
            _print_error(
                "fingerprint(s) not present in current findings: "
                + ", ".join(sorted(unknown))
            )
            return int(ExitCode.SCAN_ERROR)

    if not selected:
        _print_error("no matching findings to accept")
        return int(ExitCode.SCAN_ERROR)

    expiry_days = args.expiry_days or config.baseline.default_expiry_days
    accepted_by = os.environ.get("USER", "")
    # ``build_entries_for_accept`` (vs ``build_entry``) expands DAST
    # findings into their coarse alias entries too, so a single
    # ``baseline accept --fingerprint <fine>`` suppresses the
    # ``param``-less variant of the same advisory. Codex Phase-2-D
    # diff review pinned this — without the expansion, "fine accept"
    # silently leaves the coarse variant unsuppressed.
    from .baseline import BaselineEntry as _BaselineEntry  # local alias

    expanded: list[_BaselineEntry] = []
    for f in selected:
        expanded.extend(
            build_entries_for_accept(
                f,
                reason=args.reason,
                accepted_by=accepted_by,
                expiry_days=expiry_days,
            )
        )
    new_entries = tuple(expanded)

    existing = load_baseline(config.baseline.path)
    merged = merge_entries(existing, new_entries, accepted_by=accepted_by)
    save_baseline(merged, config.baseline.path)

    sys.stdout.write(
        f"accepted {len(new_entries)} finding(s) into {config.baseline.path}\n"
    )
    return int(ExitCode.OK)


def _baseline_list(config: ProjectConfig) -> int:
    baseline = load_baseline(config.baseline.path)
    if baseline is None or not baseline.entries:
        sys.stdout.write(f"no baseline at {config.baseline.path}\n")
        return int(ExitCode.OK)
    sys.stdout.write(
        f"baseline {config.baseline.path}: {len(baseline.entries)} entry/entries\n"
    )
    for entry in baseline.entries:
        loc = entry.source_location or "-"
        sys.stdout.write(
            f"  {entry.fingerprint[:12]}  {entry.scanner}:{entry.rule_id}  "
            f"{loc}  expires={entry.expires_at.date().isoformat()}  "
            f"by={entry.accepted_by or '-'}  reason={entry.reason!r}\n"
        )
    return int(ExitCode.OK)


def _baseline_prune(config: ProjectConfig) -> int:
    baseline = load_baseline(config.baseline.path)
    if baseline is None:
        sys.stdout.write(f"no baseline at {config.baseline.path}\n")
        return int(ExitCode.OK)
    pruned = prune_expired(baseline)
    removed = len(baseline.entries) - len(pruned.entries)
    save_baseline(pruned, config.baseline.path)
    sys.stdout.write(f"pruned {removed} expired entry/entries\n")
    return int(ExitCode.OK)


# --- Helpers ---------------------------------------------------------------


def _apply_cli_overrides(config: ProjectConfig, args: argparse.Namespace) -> ProjectConfig:
    """Override ProjectConfig with CLI flags. CLI wins over config file."""
    new = config
    if getattr(args, "fail_on", None) is not None:
        new = replace(new, fail_on=Severity.from_name(args.fail_on))

    if getattr(args, "skip", None):
        skip_set = set(new.skip) | set(args.skip)
        new = replace(new, skip=tuple(sorted(skip_set)))

    if getattr(args, "semgrep_config", None):
        new = replace(
            new,
            sast=replace(new.sast, semgrep_config=tuple(args.semgrep_config)),
        )

    if getattr(args, "allow_missing_lockfile", False):
        new = replace(new, deps=replace(new.deps, allow_missing_lockfile=True))

    # DAST CLI overrides — only the ``dast`` subcommand defines these
    # arguments, but ``getattr(..., None)`` lets us run a single block
    # without per-command branching.
    target = getattr(args, "target", None)
    if isinstance(target, str) and target:
        new = replace(new, dast=replace(new.dast, target=target))
    zap_image = getattr(args, "zap_image", None)
    if isinstance(zap_image, str) and zap_image:
        new = replace(new, dast=replace(new.dast, image=zap_image))
    if getattr(args, "ajax_spider", False):
        new = replace(new, dast=replace(new.dast, ajax_spider=True))
    zap_config_file = getattr(args, "zap_config_file", None)
    if isinstance(zap_config_file, str) and zap_config_file:
        new = replace(new, dast=replace(new.dast, config_file=zap_config_file))
    zap_network = getattr(args, "zap_network", None)
    if isinstance(zap_network, str) and zap_network:
        new = replace(new, dast=replace(new.dast, network_mode=zap_network))
    dast_mode = getattr(args, "mode", None)
    if isinstance(dast_mode, str) and dast_mode:
        new = replace(new, dast=replace(new.dast, mode=dast_mode))

    trivy_image = getattr(args, "trivy_image", None)
    if isinstance(trivy_image, str) and trivy_image:
        new = replace(new, config=replace(new.config, image=trivy_image))

    if getattr(args, "no_baseline", False):
        # Easiest way to disable baseline: point it at a path that won't
        # exist. We do not mutate the file; we just opt out of loading.
        new = replace(
            new,
            baseline=replace(new.baseline, path=Path("/dev/null/secscan-disabled")),
        )

    return new


def _build_scanner_instances(
    config: ProjectConfig, *, command: str
) -> list[Scanner]:
    """Instantiate the configured scanners.

    DAST is filtered out when no target is configured. For the dedicated
    ``dast`` subcommand the argparse layer already enforces ``--target``,
    so by the time we reach here the resolved config has a target.

    For ``secscan all``, DAST is included only if ``dast.target`` is set
    in config (or has been overridden via flags), matching the Phase 2-D
    design's "DAST is opt-in" invariant.
    """
    instances: list[Scanner] = []
    target_configured = bool(config.dast.target.strip())
    for cls in ALL_SCANNERS:
        if cls.name == "dast" and not target_configured and command != "dast":
            continue
        instances.append(cls())
    return instances


def _should_use_color(args: argparse.Namespace, stream: object) -> bool:
    if getattr(args, "no_color", False):
        return False
    # Honor NO_COLOR (https://no-color.org).
    if os.environ.get("NO_COLOR"):
        return False
    isatty_fn = getattr(stream, "isatty", None)
    return bool(callable(isatty_fn) and isatty_fn())


def _print_error(message: str) -> None:
    sys.stderr.write(f"secscan: error: {message}\n")
