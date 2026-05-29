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
from .scanners.apifuzz import ApifuzzScanner
from .scanners.base import Scanner
from .scanners.config_scanner import ConfigScanner
from .scanners.dast import DastScanner
from .scanners.deps_scanner import DepsScanner
from .scanners.iast import IastScanner
from .scanners.image import ImageScanner
from .scanners.sast import SastScanner
from .scanners.sbom import SbomScanner
from .scanners.secrets import SecretsScanner
from .scanners.supply import SupplyScanner

# Registry of scanners available in this build.
ALL_SCANNERS: list[type[Scanner]] = [
    SecretsScanner,
    DepsScanner,
    SastScanner,
    DastScanner,
    ConfigScanner,
    ImageScanner,
    SbomScanner,
    ApifuzzScanner,
    IastScanner,
    SupplyScanner,
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

    # secscan secrets / deps / sast / dast / config / image / sbom /
    # apifuzz / all
    for cmd in (
        "secrets",
        "deps",
        "sast",
        "dast",
        "config",
        "image",
        "sbom",
        "apifuzz",
        "iast",
        "supply",
        "all",
    ):
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
                    "sast, dast, config, image, sbom, apifuzz. (iast is "
                    "never included in 'secscan all' — see README.)"
                ),
            )
            # Phase 2-X: parallel orchestration knobs.
            sub.add_argument(
                "--no-parallel",
                dest="parallel",
                action="store_false",
                default=True,
                help=(
                    "run scanners serially (default: parallel). "
                    "Output is byte-identical between modes; this flag is "
                    "a performance dial only. Useful for debugging or for "
                    "downstream CI that depends on deterministic timing."
                ),
            )
            sub.add_argument(
                "--max-workers",
                type=int,
                default=None,
                metavar="N",
                help=(
                    "cap the thread pool size for parallel scans. Default: "
                    "min(cpu_count, plan_size, 8). Has no effect with "
                    "--no-parallel. Must be >= 1."
                ),
            )
            # Phase 2-Y: differential scanning.
            sub.add_argument(
                "--since",
                default=None,
                metavar="REF",
                help=(
                    "differential scan: report only what changed since git "
                    "<REF>. Requires a CLEAN working tree and that --path is "
                    "the repository root. secrets/sast run true delta scans; "
                    "deps/supply run FULL (their CVEs come from an advisory "
                    "DB, not file changes); dast/image/apifuzz/config/sbom "
                    "are SKIPPED. This is a delta check, NOT a full audit — "
                    "unchanged files are not scanned by secrets/sast."
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
        if cmd == "supply":
            sub.add_argument(
                "--verify-image",
                action="append",
                default=None,
                metavar="REF",
                dest="supply_verify_image",
                help=(
                    "Target OCI image to cosign-verify (repeatable). "
                    "Digest-pinned form required. Pair with "
                    "--signer-identity and --signer-issuer."
                ),
            )
            sub.add_argument(
                "--signer-identity",
                default=None,
                metavar="ID",
                dest="supply_signer_identity",
                help=(
                    "cosign --certificate-identity (literal match). "
                    "Applied to the LAST --verify-image."
                ),
            )
            sub.add_argument(
                "--signer-identity-regexp",
                default=None,
                metavar="REGEX",
                dest="supply_signer_identity_regexp",
                help=(
                    "cosign --certificate-identity-regexp. CLI-only, "
                    "opt-in alternative to --signer-identity."
                ),
            )
            sub.add_argument(
                "--signer-issuer",
                default=None,
                metavar="URL",
                dest="supply_signer_issuer",
                help=(
                    "cosign --certificate-oidc-issuer (e.g. "
                    "https://token.actions.githubusercontent.com)."
                ),
            )
            sub.add_argument(
                "--check-lockfile",
                action="append",
                default=None,
                metavar="PATH",
                dest="supply_check_lockfile",
                help=(
                    "Lockfile to check for self-consistency "
                    "(repeatable). Supports package-lock.json, "
                    "Pipfile.lock, uv.lock."
                ),
            )
            sub.add_argument(
                "--cosign-image",
                default=None,
                metavar="IMAGE",
                dest="supply_cosign_image",
                help=(
                    "OCI image reference (digest-pinned) for the "
                    "Sigstore cosign container."
                ),
            )
        if cmd == "iast":
            sub.add_argument(
                "--command",
                required=False,
                default=None,
                metavar="ARGV",
                dest="iast_command",
                help=(
                    "Shell-style command string for the app to spawn "
                    "(parsed with shlex.split, then Popen shell=False). "
                    "CLI-only — cannot be set from .secscan.toml."
                ),
            )
            sub.add_argument(
                "--probe-url",
                required=False,
                default=None,
                metavar="URL",
                dest="iast_probe_url",
                help=(
                    "Base URL the harness sends probes to. MUST resolve "
                    "exclusively to loopback (127.0.0.1, ::1, localhost). "
                    "CLI-only."
                ),
            )
            sub.add_argument(
                "--pyrasp-log",
                required=False,
                default=None,
                metavar="PATH",
                dest="iast_pyrasp_log",
                help=(
                    "Path the operator's app will write pyrasp events to. "
                    "Must not pre-exist (stale events would poison the "
                    "parse). Must be inside the scan root. CLI-only."
                ),
            )
            sub.add_argument(
                "--allow-risky-probes",
                action="store_true",
                dest="iast_allow_risky",
                help=(
                    "Opt in to risky probe payloads (AWS IMDS, time-"
                    "based blind SQLi, sleep-based RCE). CLI-only."
                ),
            )
            sub.add_argument(
                "--app-ready-timeout",
                type=float,
                default=None,
                metavar="SECONDS",
                dest="iast_app_ready_timeout",
                help=(
                    "How long to wait for the spawned app to start "
                    "accepting TCP connections before giving up "
                    "(default 60)."
                ),
            )
        if cmd == "apifuzz":
            sub.add_argument(
                "--api-url",
                default=None,
                metavar="URL",
                dest="apifuzz_api_url",
                help=(
                    "Base URL of the live API to fuzz (http:// or "
                    "https://). Required. No query/fragment/userinfo."
                ),
            )
            sub.add_argument(
                "--schema",
                default=None,
                metavar="PATH_OR_URL",
                dest="apifuzz_schema",
                help=(
                    "OpenAPI schema source: http(s):// URL or local "
                    "file (.yaml / .yml / .json). Required."
                ),
            )
            sub.add_argument(
                "--mode",
                choices=("baseline", "active"),
                default=None,
                dest="apifuzz_mode",
                help=(
                    "Schemathesis test method scope. 'baseline' = "
                    "GET/HEAD/OPTIONS only (safe for production). "
                    "'active' = all methods (DESTRUCTIVE — requires "
                    "--allow-active)."
                ),
            )
            sub.add_argument(
                "--allow-active",
                action="store_true",
                dest="apifuzz_allow_active",
                help=(
                    "CLI-only second opt-in for --mode=active. Cannot "
                    "be set from config. Active mode sends POST/PUT/"
                    "PATCH/DELETE which mutates target state — do NOT "
                    "point at production."
                ),
            )
            sub.add_argument(
                "--auth-header",
                action="append",
                default=None,
                metavar='"Name: Value"',
                dest="apifuzz_auth_headers",
                help=(
                    "HTTP header to inject into every Schemathesis "
                    "request (repeatable). e.g. --auth-header "
                    "'Authorization: Bearer <jwt>'. Same validator as "
                    "Phase 2-K DAST."
                ),
            )
            sub.add_argument(
                "--schemathesis-image",
                default=None,
                metavar="IMAGE",
                dest="apifuzz_scanner_image",
                help=(
                    "OCI image reference (digest-pinned) for the "
                    "Schemathesis container."
                ),
            )
            sub.add_argument(
                "--max-examples",
                type=int,
                default=None,
                metavar="N",
                dest="apifuzz_max_examples",
                help=(
                    "Maximum number of generated test cases per API "
                    "operation (Schemathesis --max-examples)."
                ),
            )
            sub.add_argument(
                "--seed",
                type=int,
                default=None,
                metavar="N",
                dest="apifuzz_seed",
                help=(
                    "Fixed Hypothesis seed for reproducible runs "
                    "(Schemathesis --seed)."
                ),
            )
            sub.add_argument(
                "--unsafe-allow-schema-outside-scan-root",
                action="store_true",
                dest="apifuzz_unsafe_allow_outside_scan_root",
                help=(
                    "Allow a CLI-supplied schema FILE that lives "
                    "outside the scan root. CONFIG-supplied schema "
                    "files are ALWAYS confined to the scan root."
                ),
            )
        if cmd == "sbom":
            sub.add_argument(
                "--target",
                action="append",
                default=None,
                metavar="T",
                dest="sbom_targets",
                help=(
                    "SBOM target (repeatable). Either: (a) an existing "
                    "local directory, (b) an existing SBOM JSON file "
                    "(.cdx.json / .spdx.json), or (c) a digest-pinned "
                    "OCI image ref. Unions with [sbom].targets in "
                    ".secscan.toml."
                ),
            )
            sub.add_argument(
                "--syft-image",
                default=None,
                metavar="IMAGE",
                dest="sbom_syft_image",
                help=(
                    "OCI image reference (digest-pinned) for the Anchore "
                    "Syft scanner container."
                ),
            )
            sub.add_argument(
                "--grype-image",
                default=None,
                metavar="IMAGE",
                dest="sbom_grype_image",
                help=(
                    "OCI image reference (digest-pinned) for the Anchore "
                    "Grype scanner container."
                ),
            )
            sub.add_argument(
                "--platform",
                default=None,
                metavar="OS/ARCH",
                dest="sbom_platform",
                help=(
                    "Platform forwarded to Syft for image targets "
                    "(default: linux/amd64). Multi-arch index digests "
                    "resolve deterministically via this flag."
                ),
            )
            sub.add_argument(
                "--unsafe-allow-targets-outside-scan-root",
                action="store_true",
                dest="sbom_unsafe_allow_outside_scan_root",
                help=(
                    "Allow CLI-supplied path / SBOM-file targets that "
                    "live outside the scan root. CONFIG-supplied targets "
                    "are ALWAYS confined. Use only when an operator "
                    "explicitly wants to scan a directory outside the "
                    "current scan tree."
                ),
            )
        if cmd == "image":
            sub.add_argument(
                "--image",
                action="append",
                default=None,
                metavar="REF",
                dest="image_refs",
                help=(
                    "target OCI image to scan (repeatable). Format: "
                    "'<repo>[:tag]@sha256:<64 hex>' (digest pinning is "
                    "required). Unions with [image].refs in .secscan.toml."
                ),
            )
            sub.add_argument(
                "--trivy-image",
                default=None,
                metavar="IMAGE",
                dest="image_scanner_image",
                help=(
                    "OCI image reference (digest-pinned) for the Trivy "
                    "scanner container. Format: "
                    "'<repo>[:tag]@sha256:<64 hex>'."
                ),
            )
            sub.add_argument(
                "--platform",
                default=None,
                metavar="OS/ARCH",
                dest="image_platform",
                help=(
                    "docker --platform value (default: linux/amd64). "
                    "Forwarded to both the docker layer and Trivy so "
                    "multi-arch index digests resolve deterministically."
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
            sub.add_argument(
                "--auth-header",
                action="append",
                default=None,
                metavar='"Name: Value"',
                dest="auth_headers",
                help=(
                    "HTTP header to inject into every ZAP request "
                    "(repeatable). Use for token-authenticated DAST: "
                    "e.g. --auth-header 'Authorization: Bearer <jwt>'. "
                    "ZAP's replacer config will add the header on all "
                    "outgoing requests so probes reach auth-gated "
                    "endpoints."
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

    # Phase 2-M: ``secscan image`` requires at least one non-blank
    # target ref. Same false-green guard as above: silently scanning
    # zero images but exiting 0 would let CI report "image scan
    # clean" when in fact nothing was scanned.
    #
    # Codex Phase 2-M diff review: count refs *after* stripping
    # whitespace and dropping empties — a config-side
    # ``[image].refs = [" "]`` would otherwise pass tuple-truthiness
    # and reach the scanner as a no-op.
    if args.command == "image":
        non_blank_refs = [r for r in config.image.refs if r and r.strip()]
        if not non_blank_refs:
            _print_error(
                "secscan image requires at least one target image. Pass "
                "--image '<repo>[:tag]@sha256:<digest>' (repeatable) or "
                "set [image].refs in .secscan.toml."
            )
            return int(ExitCode.SCAN_ERROR)

    # Phase 2-P: ``secscan iast`` requires command + probe-url +
    # pyrasp-log all three. Missing any → usage error. The IAST
    # harness is the only scanner that NEVER runs from ``secscan
    # all`` — operators must invoke it explicitly (Codex MUST-FIX
    # #1 carry-over: spawning the operator's app under operator
    # credentials needs a deliberate, interactive operator action).
    if args.command == "iast":
        if not config.iast.command.strip():
            _print_error(
                "secscan iast requires --command (the shell-style "
                "argv for the app to spawn)."
            )
            return int(ExitCode.SCAN_ERROR)
        if not config.iast.probe_url.strip():
            _print_error(
                "secscan iast requires --probe-url (the loopback "
                "base URL the harness sends probes to)."
            )
            return int(ExitCode.SCAN_ERROR)
        if not config.iast.pyrasp_log.strip():
            _print_error(
                "secscan iast requires --pyrasp-log (the path the "
                "app will write pyrasp events to; must not pre-exist)."
            )
            return int(ExitCode.SCAN_ERROR)

    # Phase 2-Q: ``secscan supply`` requires at least one
    # verify-image OR one --check-lockfile. Both empty → usage
    # error (same false-green guard as image / sbom).
    if args.command == "supply":
        n_verify = len(
            [v for v in config.supply.verify_images if v.ref.strip()]
        )
        n_locks = len(
            [
                lf
                for lf in (
                    *config.supply.lockfiles,
                    *config.supply.cli_lockfiles,
                )
                if lf.strip()
            ]
        )
        if n_verify == 0 and n_locks == 0:
            _print_error(
                "secscan supply requires at least one --verify-image "
                "(with --signer-identity + --signer-issuer) or one "
                "--check-lockfile. Both empty → nothing to scan."
            )
            return int(ExitCode.SCAN_ERROR)

    # Phase 2-O: ``secscan apifuzz`` requires both api-url AND
    # schema. Either missing → usage error (same false-green guard
    # as image / sbom).
    if args.command == "apifuzz":
        if not config.apifuzz.api_url.strip():
            _print_error(
                "secscan apifuzz requires --api-url (or "
                "[apifuzz].api_url in .secscan.toml)."
            )
            return int(ExitCode.SCAN_ERROR)
        if not config.apifuzz.schema.strip():
            _print_error(
                "secscan apifuzz requires --schema "
                "(http(s):// URL or local file)."
            )
            return int(ExitCode.SCAN_ERROR)

    # Phase 2-N: ``secscan sbom`` requires at least one non-blank
    # target. Same false-green guard as ``secscan image``.
    if args.command == "sbom":
        non_blank_targets = [
            t
            for t in (*config.sbom.targets, *config.sbom.cli_targets)
            if t and t.strip()
        ]
        if not non_blank_targets:
            _print_error(
                "secscan sbom requires at least one target. Pass "
                "--target <path-or-image> (repeatable) or set "
                "[sbom].targets in .secscan.toml."
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
    # Phase 2-X: only ``secscan all`` accepts ``--no-parallel`` /
    # ``--max-workers``. For single-scanner subcommands these
    # attributes are absent on ``args``; default to serial mode for
    # those (single-item plans are run serially regardless anyway,
    # see orchestrator.run_scanners).
    parallel = bool(getattr(args, "parallel", False))
    max_workers = getattr(args, "max_workers", None)
    if max_workers is not None and max_workers < 1:
        _print_error(
            f"--max-workers must be >= 1, got {max_workers}"
        )
        return int(ExitCode.SCAN_ERROR)

    # Phase 2-Y: resolve the diff baseline when --since was given. This
    # validates all diff-mode preconditions (repo-root, clean worktree,
    # ref resolves) and normalises to a merge-base OID. A DiffScanError
    # is a usage problem → SCAN_ERROR with the actionable message.
    diff_baseline = None
    since_ref = getattr(args, "since", None)
    if since_ref is not None:
        from .diffscan import DiffScanError, resolve_diff_baseline

        try:
            diff_baseline = resolve_diff_baseline(
                since_ref, scan_root=scan_root.resolved, runner=runner
            )
        except DiffScanError as exc:
            _print_error(f"diff scan: {exc}")
            return int(ExitCode.SCAN_ERROR)

    try:
        outcome = run_scanners(
            scanners,
            scan_root=scan_root,
            config=config,
            runner=runner,
            only=only,
            parallel=parallel,
            max_workers=max_workers,
            diff_baseline=diff_baseline,
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

    # Phase 2-Y (Codex design review #6): if --since selected ZERO
    # diff-aware scanners that actually ran (e.g. the user combined
    # --since with a --skip set that removed secrets/sast/deps/supply,
    # leaving only AGNOSTIC scanners), that is an inconclusive scan, not
    # a clean one. Fail loudly rather than exit 0 on an empty delta.
    diff_zero_runnable = (
        diff_baseline is not None and not final_result.scanned_scanners
    )
    if diff_baseline is not None and diff_zero_runnable:
        from dataclasses import replace as _replace

        final_result = _replace(
            final_result,
            warnings=(
                *final_result.warnings,
                f"diff scan (--since {diff_baseline.user_ref}): no diff-aware "
                "scanner ran. Every selected scanner is skipped in diff mode "
                "(secrets/sast/deps/supply support --since; "
                "dast/image/apifuzz/config/sbom do not). Nothing was checked.",
            ),
        )

    # When ``all`` is partial, we must not exit 0 on findings==0. The user
    # asked for "everything" and got "subset"; that's an inconclusive scan
    # for CI purposes, not a clean one. Same logic for a zero-runnable diff.
    if (missing_for_all or diff_zero_runnable) and (
        outcome.decision.exit_code == ExitCode.OK
    ):
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
    # Codex Phase 2-X diff review MUST-FIX #4: baseline accept is
    # an attended, audit-trail-producing operation. The benefit of
    # parallel speedup here is small (single discovery, modest
    # plan) and the cost of any non-determinism in error / warning
    # ordering during a critical workflow outweighs it. Force the
    # serial path; the parallel orchestrator's default-True does
    # NOT apply to baseline.
    outcome = run_scanners(
        scanners,
        scan_root=resolve_scan_root(str(scan_root)),
        config=config,
        runner=runner,
        parallel=False,
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

    # Phase 2-M image-scanner CLI overrides. Each is a no-op when the
    # current subcommand didn't define the argparse field.
    image_refs = getattr(args, "image_refs", None)
    if image_refs:
        # CLI union config (Codex Phase 2-M design pin): an operator running
        # ``secscan image --image foo`` while ``.secscan.toml`` also has
        # ``[image].refs = ["bar"]`` should scan BOTH. The scanner
        # adapter dedupes by ref string so a duplicate is harmless.
        #
        # Codex Phase 2-M diff review: strip and drop blank entries
        # HERE rather than relying on the scanner's later filter.
        # ``--image "" --image " "`` would otherwise inflate refs
        # into a non-empty tuple that passes the dispatcher's
        # "zero refs → usage error" guard, only to be filtered to
        # empty inside the scanner — producing the silent-pass
        # false-green the guard exists to prevent.
        merged: list[str] = list(new.image.refs)
        for ref in image_refs:
            if not isinstance(ref, str):
                continue
            cleaned = ref.strip()
            if not cleaned:
                continue
            if cleaned not in merged:
                merged.append(cleaned)
        new = replace(new, image=replace(new.image, refs=tuple(merged)))
    image_scanner_image = getattr(args, "image_scanner_image", None)
    if isinstance(image_scanner_image, str) and image_scanner_image:
        new = replace(
            new, image=replace(new.image, image=image_scanner_image)
        )
    image_platform = getattr(args, "image_platform", None)
    if isinstance(image_platform, str) and image_platform:
        new = replace(
            new, image=replace(new.image, platform=image_platform)
        )

    # Phase 2-N sbom-scanner CLI overrides. Same blank-stripping
    # discipline as Phase 2-M's image refs (Codex Phase 2-M diff
    # review FIX_NEEDED) — a ``--target " "`` must NOT inflate
    # the dispatcher's "zero targets" check into a non-empty tuple
    # that then becomes a silent no-op inside the scanner.
    sbom_targets = getattr(args, "sbom_targets", None)
    if sbom_targets:
        # Codex Phase 2-N diff review MUST-FIX (security): CLI
        # targets land in a SEPARATE ``cli_targets`` slot so the
        # scanner can apply confinement per-origin. Merging them
        # into ``targets`` would let the CLI-only unconfine flag
        # also unconfine config-supplied targets — a privilege
        # widening across trust boundaries.
        merged_cli: list[str] = list(new.sbom.cli_targets)
        for t in sbom_targets:
            if not isinstance(t, str):
                continue
            cleaned = t.strip()
            if not cleaned:
                continue
            if cleaned not in merged_cli and cleaned not in new.sbom.targets:
                merged_cli.append(cleaned)
        new = replace(
            new, sbom=replace(new.sbom, cli_targets=tuple(merged_cli))
        )
    sbom_syft_image = getattr(args, "sbom_syft_image", None)
    if isinstance(sbom_syft_image, str) and sbom_syft_image:
        new = replace(
            new, sbom=replace(new.sbom, syft_image=sbom_syft_image)
        )
    sbom_grype_image = getattr(args, "sbom_grype_image", None)
    if isinstance(sbom_grype_image, str) and sbom_grype_image:
        new = replace(
            new, sbom=replace(new.sbom, grype_image=sbom_grype_image)
        )
    sbom_platform = getattr(args, "sbom_platform", None)
    if isinstance(sbom_platform, str) and sbom_platform:
        new = replace(
            new, sbom=replace(new.sbom, platform=sbom_platform)
        )
    if getattr(args, "sbom_unsafe_allow_outside_scan_root", False):
        # Codex Phase 2-N diff review MUST-FIX (security): the
        # unconfine flag is CLI-only and applies ONLY to CLI
        # targets. Config-supplied ``[sbom].targets`` are still
        # confined to the scan root regardless.
        new = replace(
            new, sbom=replace(new.sbom, unconfine_cli_targets=True)
        )

    # Phase 2-O apifuzz CLI overrides.
    af_api_url = getattr(args, "apifuzz_api_url", None)
    if isinstance(af_api_url, str) and af_api_url:
        new = replace(new, apifuzz=replace(new.apifuzz, api_url=af_api_url))
    af_schema = getattr(args, "apifuzz_schema", None)
    if isinstance(af_schema, str) and af_schema:
        # Codex Phase 2-N MUST-FIX (security) carry-over: mark the
        # schema as CLI-origin so the scanner adapter can apply the
        # CLI-only unconfine flag without affecting any config-
        # supplied schema that was already set.
        new = replace(
            new,
            apifuzz=replace(
                new.apifuzz, schema=af_schema, schema_from_cli=True
            ),
        )
    af_mode = getattr(args, "apifuzz_mode", None)
    if isinstance(af_mode, str) and af_mode:
        new = replace(new, apifuzz=replace(new.apifuzz, mode=af_mode))
    af_scanner_image = getattr(args, "apifuzz_scanner_image", None)
    if isinstance(af_scanner_image, str) and af_scanner_image:
        new = replace(
            new, apifuzz=replace(new.apifuzz, scanner_image=af_scanner_image)
        )
    af_max_examples = getattr(args, "apifuzz_max_examples", None)
    if isinstance(af_max_examples, int) and af_max_examples > 0:
        new = replace(
            new, apifuzz=replace(new.apifuzz, max_examples=af_max_examples)
        )
    af_seed = getattr(args, "apifuzz_seed", None)
    if isinstance(af_seed, int) and not isinstance(af_seed, bool):
        new = replace(new, apifuzz=replace(new.apifuzz, seed=af_seed))
    af_auth = getattr(args, "apifuzz_auth_headers", None)
    if af_auth:
        merged_h: list[str] = list(new.apifuzz.headers)
        for h in af_auth:
            if not isinstance(h, str):
                continue
            cleaned = h.strip()
            if cleaned and cleaned not in merged_h:
                merged_h.append(cleaned)
        new = replace(
            new, apifuzz=replace(new.apifuzz, headers=tuple(merged_h))
        )
    if getattr(args, "apifuzz_allow_active", False):
        # Codex Phase 2-O design review MUST-FIX #2: ``allow_active``
        # is CLI-only. The config parser cannot set it; only this
        # override path can. ``mode = "active"`` in config without
        # this CLI flag will fail the scanner's mode validator.
        new = replace(new, apifuzz=replace(new.apifuzz, allow_active=True))
    if getattr(args, "apifuzz_unsafe_allow_outside_scan_root", False):
        new = replace(
            new, apifuzz=replace(new.apifuzz, unconfine_cli_schema=True)
        )

    # Phase 2-P IAST CLI overrides. ALL iast fields are CLI-only
    # (the config parser rejects ``[iast]`` keys outright) so this
    # is the SOLE writer of ``ProjectConfig.iast``.
    iast_command = getattr(args, "iast_command", None)
    if isinstance(iast_command, str) and iast_command:
        new = replace(new, iast=replace(new.iast, command=iast_command))
    iast_probe_url = getattr(args, "iast_probe_url", None)
    if isinstance(iast_probe_url, str) and iast_probe_url:
        new = replace(new, iast=replace(new.iast, probe_url=iast_probe_url))
    iast_pyrasp_log = getattr(args, "iast_pyrasp_log", None)
    if isinstance(iast_pyrasp_log, str) and iast_pyrasp_log:
        new = replace(new, iast=replace(new.iast, pyrasp_log=iast_pyrasp_log))
    if getattr(args, "iast_allow_risky", False):
        new = replace(new, iast=replace(new.iast, allow_risky_probes=True))
    iast_ready = getattr(args, "iast_app_ready_timeout", None)
    if isinstance(iast_ready, (int, float)) and iast_ready > 0:
        new = replace(
            new, iast=replace(new.iast, app_ready_timeout=float(iast_ready))
        )

    # Phase 2-Q supply chain CLI overrides. ``--verify-image`` +
    # ``--signer-identity`` + ``--signer-issuer`` together form
    # ONE verification (the last triple applies). Multiple
    # invocations require repeating all three flags; secscan
    # treats each ``--verify-image`` instance as a separate
    # entry pulling the matching signer flags.
    sup_imgs = getattr(args, "supply_verify_image", None)
    sup_ident = getattr(args, "supply_signer_identity", None)
    sup_ident_re = getattr(args, "supply_signer_identity_regexp", None)
    sup_issuer = getattr(args, "supply_signer_issuer", None)
    if sup_imgs:
        from .config import SupplyVerifyImage

        merged_imgs: list[SupplyVerifyImage] = list(new.supply.verify_images)
        for ref in sup_imgs:
            if not isinstance(ref, str) or not ref.strip():
                continue
            merged_imgs.append(
                SupplyVerifyImage(
                    ref=ref.strip(),
                    signer_identity=(sup_ident or "").strip(),
                    signer_identity_regexp=(sup_ident_re or "").strip(),
                    signer_issuer=(sup_issuer or "").strip(),
                )
            )
        new = replace(
            new, supply=replace(new.supply, verify_images=tuple(merged_imgs))
        )

    sup_locks = getattr(args, "supply_check_lockfile", None)
    if sup_locks:
        # CLI-origin lockfiles bypass scan-root confinement —
        # they go into a separate ``cli_lockfiles`` slot
        # (Codex Phase 2-Q design review carry-over).
        merged_locks = list(new.supply.cli_lockfiles)
        for lf in sup_locks:
            if not isinstance(lf, str) or not lf.strip():
                continue
            stripped = lf.strip()
            if stripped not in merged_locks:
                merged_locks.append(stripped)
        new = replace(
            new,
            supply=replace(new.supply, cli_lockfiles=tuple(merged_locks)),
        )

    sup_cosign_image = getattr(args, "supply_cosign_image", None)
    if isinstance(sup_cosign_image, str) and sup_cosign_image:
        new = replace(
            new, supply=replace(new.supply, cosign_image=sup_cosign_image)
        )

    auth_headers = getattr(args, "auth_headers", None)
    if auth_headers:
        new = replace(
            new,
            dast=replace(new.dast, auth_headers=tuple(auth_headers)),
        )

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
    image_refs_configured = bool(config.image.refs)
    sbom_targets_configured = bool(
        config.sbom.targets or config.sbom.cli_targets
    )
    apifuzz_configured = bool(
        config.apifuzz.api_url.strip() and config.apifuzz.schema.strip()
    )
    for cls in ALL_SCANNERS:
        if cls.name == "dast" and not target_configured and command != "dast":
            continue
        # Phase 2-M: image scanner is opt-in. In ``secscan all`` we
        # filter it out unless ``[image].refs`` is non-empty; the
        # dedicated ``secscan image`` subcommand always instantiates
        # it so the dispatcher can produce a clear "no refs" error
        # rather than silently skipping.
        if (
            cls.name == "image"
            and not image_refs_configured
            and command != "image"
        ):
            continue
        # Phase 2-N: same opt-in posture for sbom scanner.
        if (
            cls.name == "sbom"
            and not sbom_targets_configured
            and command != "sbom"
        ):
            continue
        # Phase 2-O: apifuzz is opt-in. Requires BOTH api_url and
        # schema. If either is missing, skip in ``secscan all``;
        # the dispatcher's separate guard handles the direct
        # ``secscan apifuzz`` case.
        if (
            cls.name == "apifuzz"
            and not apifuzz_configured
            and command != "apifuzz"
        ):
            continue
        # Phase 2-P: IAST is NEVER included in ``secscan all`` —
        # it spawns the operator's app subprocess and must be an
        # explicit, interactive operator decision. Direct
        # ``secscan iast`` invocation is the only path that
        # instantiates this scanner.
        if cls.name == "iast" and command != "iast":
            continue
        # Phase 2-Q: supply chain integrity is opt-in. ``secscan
        # all`` skips it unless [supply].verify_images or
        # [supply].lockfiles is configured.
        if cls.name == "supply" and command != "supply":
            supply_configured = bool(
                config.supply.verify_images or config.supply.lockfiles
            )
            if not supply_configured:
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
