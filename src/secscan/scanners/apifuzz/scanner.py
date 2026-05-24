"""The :class:`Scanner` adapter for the apifuzz pipeline.

Phase 2-O: drives the Alpine-helper chown → Schemathesis-run →
NDJSON-extract → cleanup sequence for one ``--api-url`` +
``--schema`` pair.

Pipeline:

1. ``docker volume create --label secscan-tmp=1
   secscan-apifuzz-<32 hex>`` — short-lived intermediate volume
   for the NDJSON report.
2. ``docker run`` Alpine helper to ``chown -R 1000:1000 /work``
   so the non-root Schemathesis container can write into it.
3. ``docker run`` Schemathesis ``run`` — produces
   ``/work/report.ndjson``.
4. Pre-flight size check via ``docker run alpine wc -c
   /work/report.ndjson`` (Codex MUST-FIX #4 — refuse to cat a
   gigabyte report into Python memory).
5. ``docker run alpine cat /work/report.ndjson`` to stream the
   contents to stdout for parsing.
6. ``docker volume rm -f`` in ``try/finally``.

Like Phase 2-N's ``SbomScanner``, this is **opt-in**: empty
``[apifuzz].api_url`` → silent skip in ``secscan all``; direct
``secscan apifuzz`` with no api-url → hard usage error.

Best-effort note on volume leaks: a SIGKILL or host crash
mid-scan will leave one ``secscan-apifuzz-<32 hex>`` volume per
killed run. Sweep with
``docker volume prune -f --filter label=secscan-tmp=1``.
"""

from __future__ import annotations

import secrets
import shutil
from dataclasses import dataclass, field

from ...models import (
    ScanConfig,
    ScannerError,
    ScanOutcome,
    WorkUnit,
)
from ...redact import redact_text, truncate
from ...runner import CommandRunner, decode_output
from ..base import Scanner, ToolNotFoundError
from ._pinned import (
    DEFAULT_HELPER_IMAGE,
    DEFAULT_SCHEMATHESIS_IMAGE,
)
from .schemathesis import (
    DEFAULT_MAX_EXAMPLES,
    SchemathesisInvocation,
    build_argv,
    build_chown_argv,
    classify_schemathesis_exit,
    parse_ndjson_report,
)
from .validators import (
    MAX_REPORT_BYTES,
    ApifuzzInputError,
    Schema,
    SchemaFile,
    assert_schema_file_under_scan_root,
    classify_schema,
    validate_api_url,
    validate_intermediate_volume_name,
    validate_mode,
)


@dataclass(frozen=True)
class ApifuzzScannerSettings:
    api_url: str = ""
    schema_raw: str = ""
    schema_from_cli: bool = False
    """When True, the schema was supplied on the CLI and may
    bypass the scan-root confinement check if the operator passed
    ``--unsafe-allow-schema-outside-scan-root``."""

    unconfine_cli_schema: bool = False
    """Set ONLY by the CLI flag. Cannot be enabled from config —
    same per-origin discipline as Phase 2-N sbom."""

    mode: str = "baseline"
    allow_active: bool = False
    """CLI-only second opt-in for ``mode=active``. Codex Phase 2-O
    design review MUST-FIX #2: an attacker-controlled
    .secscan.toml setting ``[apifuzz].mode = "active"`` must NOT
    enable active fuzzing on its own — the operator must add
    ``--allow-active`` at the CLI."""

    headers: tuple[str, ...] = field(default_factory=tuple)
    scanner_image: str = DEFAULT_SCHEMATHESIS_IMAGE
    helper_image: str = DEFAULT_HELPER_IMAGE
    max_examples: int = DEFAULT_MAX_EXAMPLES
    seed: int | None = None
    deterministic: bool = False
    request_timeout: float = 5.0


class ApifuzzScanner(Scanner):
    """Schemathesis-driven OpenAPI fuzzing scanner."""

    name = "apifuzz"
    tool_executable = "docker"
    install_hint = (
        "install Docker (https://docs.docker.com/engine/install/) and "
        "ensure the daemon is reachable. The Schemathesis image is "
        "pulled on first use."
    )

    def is_applicable(self, unit: WorkUnit) -> bool:
        # Apifuzz scans an external HTTP target — workspace-side
        # discovery doesn't apply. Always run when there's a target.
        return True

    def scan(
        self,
        unit: WorkUnit,
        runner: CommandRunner,
        config: ScanConfig,
    ) -> ScanOutcome:
        try:
            settings = _resolve_settings(config)
        except ApifuzzInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        if not settings.api_url or not settings.schema_raw:
            # Opt-in: missing api_url AND/OR schema → no-op.
            return ScanOutcome(scanner=self.name)

        if shutil.which(self.tool_executable) is None:
            raise ToolNotFoundError(self.tool_executable, self.install_hint)

        # Validate every operator-facing input up front so we never
        # spin up docker for a malformed request.
        try:
            api_url = validate_api_url(settings.api_url)
            mode = validate_mode(
                settings.mode, allow_active=settings.allow_active
            )
            schema: Schema = classify_schema(
                settings.schema_raw, source="--schema"
            )
            # Codex Phase 2-N MUST-FIX carry-over (security):
            # config-supplied schema files are ALWAYS confined to
            # the scan root. CLI-supplied schemas may opt out via
            # the CLI-only unconfine flag.
            confine_this = (
                not settings.schema_from_cli
                or not settings.unconfine_cli_schema
            )
            if confine_this and isinstance(schema, SchemaFile):
                assert_schema_file_under_scan_root(
                    schema, scan_root=unit.root
                )
        except ApifuzzInputError as exc:
            return _error_outcome(
                self.name,
                reason=str(exc),
                returncode=None,
                stderr=b"",
                duration=0.0,
            )

        volume = f"secscan-apifuzz-{secrets.token_hex(16)}"
        validate_intermediate_volume_name(volume)

        try:
            create = runner.run(
                [
                    "docker",
                    "volume",
                    "create",
                    "--label",
                    "secscan-tmp=1",
                    volume,
                ],
                cwd=unit.root,
                timeout_seconds=60,
            )
            if create.returncode != 0:
                return _error_outcome(
                    self.name,
                    reason=(
                        "failed to create apifuzz intermediate volume"
                    ),
                    returncode=create.returncode,
                    stderr=create.stderr,
                    duration=create.duration_seconds,
                )

            chown = runner.run(
                build_chown_argv(
                    helper_image=settings.helper_image, volume=volume
                ),
                cwd=unit.root,
                timeout_seconds=60,
            )
            if chown.returncode != 0:
                return _error_outcome(
                    self.name,
                    reason=(
                        "alpine helper failed to chown the apifuzz "
                        "intermediate volume"
                    ),
                    returncode=chown.returncode,
                    stderr=chown.stderr,
                    duration=chown.duration_seconds,
                )

            invocation = SchemathesisInvocation(
                schema=schema,
                api_url=api_url,
                intermediate_volume=volume,
                scanner_image=settings.scanner_image,
                mode=mode,
                headers=settings.headers,
                max_examples=settings.max_examples,
                seed=settings.seed,
                deterministic=settings.deterministic,
                request_timeout=settings.request_timeout,
            )
            run_result = runner.run(
                build_argv(invocation),
                cwd=unit.root,
                timeout_seconds=config.timeout_seconds,
            )
            ok, reason = classify_schemathesis_exit(
                run_result.returncode, timed_out=run_result.timed_out
            )
            if not ok:
                return _error_outcome(
                    self.name,
                    reason=reason or "schemathesis failed",
                    returncode=run_result.returncode,
                    stderr=run_result.stderr,
                    duration=run_result.duration_seconds,
                )

            # Pre-flight size check via Alpine helper. Codex MUST-FIX #4.
            size_check = runner.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--network=none",
                    "-v",
                    f"{volume}:/work:ro",
                    "--",
                    settings.helper_image,
                    "wc",
                    "-c",
                    "/work/report.ndjson",
                ],
                cwd=unit.root,
                timeout_seconds=30,
            )
            if size_check.returncode != 0:
                return _error_outcome(
                    self.name,
                    reason="ndjson report missing or unreadable",
                    returncode=size_check.returncode,
                    stderr=size_check.stderr,
                    duration=size_check.duration_seconds,
                )
            report_size = _parse_wc_bytes(size_check.stdout)
            if report_size is None:
                return _error_outcome(
                    self.name,
                    reason="could not determine ndjson report size",
                    returncode=size_check.returncode,
                    stderr=size_check.stderr,
                    duration=size_check.duration_seconds,
                )
            if report_size > MAX_REPORT_BYTES:
                return _error_outcome(
                    self.name,
                    reason=(
                        f"ndjson report is {report_size} bytes, exceeds "
                        f"the {MAX_REPORT_BYTES}-byte cap"
                    ),
                    returncode=None,
                    stderr=b"",
                    duration=0.0,
                )

            extract = runner.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--network=none",
                    "-v",
                    f"{volume}:/work:ro",
                    "--",
                    settings.helper_image,
                    "cat",
                    "/work/report.ndjson",
                ],
                cwd=unit.root,
                timeout_seconds=120,
            )
            if extract.returncode != 0:
                return _error_outcome(
                    self.name,
                    reason="ndjson report extraction failed",
                    returncode=extract.returncode,
                    stderr=extract.stderr,
                    duration=extract.duration_seconds,
                )

            parsed = parse_ndjson_report(extract.stdout, api_url=api_url)
            total_duration = (
                create.duration_seconds
                + chown.duration_seconds
                + run_result.duration_seconds
                + size_check.duration_seconds
                + extract.duration_seconds
            )
            warnings = list(parsed.warnings)
            warnings.extend(parsed.out_of_scope_alerts)
            return ScanOutcome(
                scanner=self.name,
                findings=parsed.findings,
                warnings=tuple(warnings),
                tool_version=parsed.tool_version,
                duration_seconds=total_duration,
            )
        finally:
            runner.run(
                ["docker", "volume", "rm", "-f", volume],
                cwd=unit.root,
                timeout_seconds=60,
            )


def _parse_wc_bytes(stdout: bytes) -> int | None:
    text = decode_output(stdout).strip()
    if not text:
        return None
    first_token = text.split()[0] if text.split() else ""
    try:
        return int(first_token)
    except ValueError:
        return None


def _resolve_settings(config: ScanConfig) -> ApifuzzScannerSettings:
    extra = config.extra

    def _str_or_default(key: str, default: str = "") -> str:
        raw = extra.get(key)
        if raw is None:
            return default
        if not isinstance(raw, str):
            raise ApifuzzInputError(f"apifuzz.{key} must be a string")
        stripped = raw.strip()
        return stripped or default

    def _bool_or_default(key: str, default: bool) -> bool:
        raw = extra.get(key, default)
        if not isinstance(raw, bool):
            raise ApifuzzInputError(f"apifuzz.{key} must be a bool")
        return raw

    headers_raw = extra.get("headers", ())
    if not isinstance(headers_raw, (list, tuple)):
        raise ApifuzzInputError("apifuzz.headers must be a list of strings")
    headers: list[str] = []
    for i, h in enumerate(headers_raw):
        if not isinstance(h, str):
            raise ApifuzzInputError(
                f"apifuzz.headers[{i}] must be a string"
            )
        stripped = h.strip()
        if stripped:
            headers.append(stripped)

    seed_raw = extra.get("seed")
    seed: int | None
    if seed_raw is None:
        seed = None
    elif isinstance(seed_raw, int) and not isinstance(seed_raw, bool):
        seed = seed_raw
    else:
        raise ApifuzzInputError("apifuzz.seed must be an integer")

    max_examples_raw = extra.get("max_examples", DEFAULT_MAX_EXAMPLES)
    if (
        not isinstance(max_examples_raw, int)
        or isinstance(max_examples_raw, bool)
        or max_examples_raw < 1
    ):
        raise ApifuzzInputError(
            "apifuzz.max_examples must be a positive integer"
        )

    request_timeout_raw = extra.get("request_timeout", 5.0)
    if not isinstance(request_timeout_raw, (int, float)) or isinstance(
        request_timeout_raw, bool
    ):
        raise ApifuzzInputError(
            "apifuzz.request_timeout must be a number"
        )

    return ApifuzzScannerSettings(
        api_url=_str_or_default("api_url"),
        schema_raw=_str_or_default("schema"),
        schema_from_cli=_bool_or_default("schema_from_cli", False),
        unconfine_cli_schema=_bool_or_default(
            "unconfine_cli_schema", False
        ),
        mode=_str_or_default("mode", "baseline"),
        allow_active=_bool_or_default("allow_active", False),
        headers=tuple(headers),
        scanner_image=_str_or_default(
            "scanner_image", DEFAULT_SCHEMATHESIS_IMAGE
        ),
        helper_image=_str_or_default("helper_image", DEFAULT_HELPER_IMAGE),
        max_examples=int(max_examples_raw),
        seed=seed,
        deterministic=_bool_or_default("deterministic", False),
        request_timeout=float(request_timeout_raw),
    )


def _error_outcome(
    scanner: str,
    *,
    reason: str,
    returncode: int | None,
    stderr: bytes,
    duration: float,
) -> ScanOutcome:
    excerpt = truncate(redact_text(decode_output(stderr)))
    return ScanOutcome(
        scanner=scanner,
        error=ScannerError(
            scanner=scanner,
            reason=reason,
            stderr_excerpt=excerpt or None,
            returncode=returncode,
        ),
        duration_seconds=duration,
    )
