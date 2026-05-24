"""Project configuration loader (``.secscan.toml``).

The config file is optional. When absent, defaults from this module are used
verbatim. When present, the parser validates types and rejects unknown keys
loudly — a typo'd ``severity_overrides`` section that silently does nothing
would be a security regression.

Path semantics: ``baseline.path`` is resolved **relative to the config file's
directory**, not the process cwd. Codex flagged the cwd-vs-config ambiguity
explicitly. If no config file is present, ``baseline.path`` is resolved
relative to ``--path``.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import Severity

CONFIG_FILENAME = ".secscan.toml"


class ConfigError(ValueError):
    """Raised on malformed or invalid configuration."""


# --- Defaults --------------------------------------------------------------

DEFAULT_FAIL_ON: Severity = Severity.HIGH
DEFAULT_DEPS_TIMEOUT = 300
DEFAULT_SAST_TIMEOUT = 900
DEFAULT_SECRETS_TIMEOUT = 300
DEFAULT_DAST_TIMEOUT = 900
DEFAULT_CONFIG_TIMEOUT = 300
DEFAULT_IMAGE_TIMEOUT = 600
DEFAULT_IMAGE_PLATFORM = "linux/amd64"
DEFAULT_BASELINE_PATH = ".secscan/baseline.json"
DEFAULT_BASELINE_EXPIRY_DAYS = 90
DEFAULT_SEMGREP_CONFIG: tuple[str, ...] = (
    # Phase 2-F + 2-G: the registry packs cover most CWE categories
    # but the bench measurement surfaced gaps the public packs do not
    # fill at all — Python ``yaml.load`` without SafeLoader (CWE-502)
    # and hard-coded credentials in named variables (CWE-798). We
    # ship our own rules for those gaps under ``secscan:extra`` and
    # lead with the sentinel so secscan's targeted rules see every
    # file before the broader packs.
    #
    # Order:
    # - ``secscan:extra`` — bundled rules (see src/secscan/rules/).
    # - ``p/default`` — broad registry pack.
    # - language-specific packs — catch-alls per ecosystem.
    # - ``p/owasp-top-ten`` — AppSec category coverage on top.
    #
    # Overlap is fine: rules that fire on the same finding from
    # multiple packs are deduplicated by the secscan Finding
    # fingerprint (``rule_id + file + line``). Codex Phase 2-F /
    # 2-G diff reviews pinned this.
    #
    # Operators who need different coverage (broader → add
    # ``p/security-audit``; narrower → drop ``p/default``) can
    # override the whole list via ``[sast].semgrep_config`` in
    # ``.secscan.toml`` or via ``--semgrep-config`` on the CLI.
    "secscan:extra",
    "p/default",
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/owasp-top-ten",
    # Phase 2-I (external-bench): the OWASP NodeGoat measurement
    # surfaced that ``p/expressjs`` reliably catches additional
    # CWE-522 (insufficient credentials protection in express
    # cookie/session config) and CWE-601 (open redirect) cases
    # that the language-only packs miss. Zero false positives on
    # the curated ``safe_*`` Python/JS fixtures.
    "p/expressjs",
)
VALID_UNKNOWN_POLICIES = frozenset({"warn", "fail", "ignore"})


# --- Dataclasses -----------------------------------------------------------


@dataclass(frozen=True)
class UnknownSeverityPolicy:
    """How ``Severity.UNKNOWN`` is treated, per scanner.

    - ``"warn"``    : counted in display but never triggers fail-on.
    - ``"fail"``    : treated as if it met the configured fail-on level.
    - ``"ignore"``  : still displayed, but excluded from the threshold check.
                      Note: even with "ignore", findings are NOT hidden — Codex
                      flagged "silent hiding" as a security regression.
    """

    deps: str = "warn"
    sast: str = "warn"
    secrets: str = "fail"
    dast: str = "warn"
    config: str = "warn"
    image: str = "warn"

    def for_scanner(self, scanner: str) -> str:
        return getattr(self, scanner, "warn")


@dataclass(frozen=True)
class DepsConfig:
    allow_missing_lockfile: bool = False
    ignore_dev_dependencies: bool = False
    timeout_seconds: int = DEFAULT_DEPS_TIMEOUT


@dataclass(frozen=True)
class SastConfig:
    semgrep_config: tuple[str, ...] = DEFAULT_SEMGREP_CONFIG
    timeout_seconds: int = DEFAULT_SAST_TIMEOUT
    allow_unverified_configs: bool = False
    """If True, accept arbitrary URLs / absolute out-of-tree paths as
    semgrep configs. Defaults False: only registry shorthand (``p/...``,
    ``r/...``) and paths under the scan root are accepted, because an
    untrusted PR that edits ``.secscan.toml`` could otherwise point
    semgrep at a malicious ruleset. Codex 12th review."""


@dataclass(frozen=True)
class SecretsConfig:
    timeout_seconds: int = DEFAULT_SECRETS_TIMEOUT
    # redact_secrets is intentionally NOT exposed. Redaction is mandatory.


@dataclass(frozen=True)
class ConfigScannerConfig:
    """Phase 2-L: ``secscan config`` (Trivy IaC scanner) configuration.

    Like DAST, the config scanner runs Trivy via docker, with the
    scan root bind-mounted read-only at ``/work``. The ``image``
    field follows the same digest-pinned convention as DAST's
    ``zap-image``.
    """

    image: str = ""
    """Empty string means "use the pinned default Trivy image"
    (see ``config_scanner/_pinned.py``)."""
    timeout_seconds: int = DEFAULT_CONFIG_TIMEOUT


@dataclass(frozen=True)
class ImageConfig:
    """Phase 2-M: ``secscan image`` (Trivy image-vulnerability) config.

    Like DAST, the image scanner is **opt-in**: it only runs when
    ``refs`` is non-empty (either set in ``.secscan.toml`` or passed
    via ``--image`` on the CLI). With ``refs=()`` the scanner is
    filtered out of ``secscan all``.

    Every target ref MUST be ``<repo>[:tag]@sha256:<64 hex>`` —
    digest pinning is enforced in
    ``secscan.scanners.image.trivy.validate_image_ref``.

    ``platform`` is forced (default ``linux/amd64``) so multi-arch
    OCI index digests resolve deterministically across hosts. Set
    ``platform = "linux/arm64"`` (etc.) to scan a different arch's
    manifest of the same index.
    """

    refs: tuple[str, ...] = ()
    """Target image references to scan. Empty → scanner is no-op
    (opt-in)."""

    image: str = ""
    """OCI image ref of the Trivy *scanner* container. Empty means
    'use the pinned default' (see ``scanners/image/_pinned.py``)."""

    platform: str = DEFAULT_IMAGE_PLATFORM
    """docker ``--platform`` value forwarded to both the docker layer
    and the Trivy CLI. Mandatory because OCI index digests vary by
    architecture and we want the same digest to mean the same scan
    on every host."""

    cache_volume: str = ""
    """Docker named volume holding a pre-seeded Trivy vulnerability
    DB. Empty (default): Trivy downloads its DB on every invocation.
    Non-empty: mounted read-only and combined with
    ``--skip-db-update`` for deterministic / offline scans (the
    bench workflow uses this)."""

    timeout_seconds: int = DEFAULT_IMAGE_TIMEOUT


@dataclass(frozen=True)
class DastConfig:
    """Phase 2-D DAST scanner configuration.

    Unlike the other scanners, DAST is opt-in: it only runs when a
    ``target`` URL is configured (either via ``--target`` on the CLI
    or ``dast.target`` in ``.secscan.toml``). With ``target=""`` the
    scanner is filtered out of ``secscan all``.

    ``image`` MUST be of the form ``<repo>[:tag]@sha256:<64 hex>`` —
    digest pinning is enforced in
    ``secscan.scanners.dast.zap.validate_image_ref``. The default value
    points at the upstream ZAP image but with an all-zeroes digest; the
    operator is expected to supply a verified digest the first time
    they enable DAST.

    ``network_mode``: ``bridge`` (default) or ``host``. Use ``host``
    only when the DAST target is reachable only on the host network
    namespace (e.g. a dev server bound to 127.0.0.1).
    """

    target: str = ""
    image: str = ""
    """Empty string means "use the pinned default" (see ``dast/_pinned.py``)."""
    ajax_spider: bool = False
    config_file: str = ""
    network_mode: str = "bridge"
    timeout_seconds: int = DEFAULT_DAST_TIMEOUT
    mode: str = "baseline"
    """Phase 2-J: ``baseline`` (passive, ~3 min) or ``active``
    (sends payloads — SQLi / XSS / auth-bypass — ~30-60 min).
    Active mode catches CWE-287 / CWE-89 / CWE-79 patterns the
    baseline misses but MUST NOT be pointed at production
    targets; it will issue malformed requests that can degrade
    service or create user-visible test rows."""

    auth_headers: tuple[str, ...] = ()
    """Phase 2-K: HTTP headers to inject into every ZAP request.

    Each entry is ``"Name: Value"`` (e.g.
    ``"Authorization: Bearer <jwt>"``). The DastScanner forwards
    them to ZAP's ``replacer`` config so every probe carries the
    header — required to reach auth-gated endpoints during DAST.
    Validated via ``dast.zap.validate_auth_header`` before
    reaching the argv."""


@dataclass(frozen=True)
class BaselineConfig:
    path: Path = Path(DEFAULT_BASELINE_PATH)
    default_expiry_days: int = DEFAULT_BASELINE_EXPIRY_DAYS


@dataclass(frozen=True)
class ProjectConfig:
    fail_on: Severity = DEFAULT_FAIL_ON
    skip: tuple[str, ...] = ()
    severity_unknown_policy: UnknownSeverityPolicy = field(default_factory=UnknownSeverityPolicy)
    deps: DepsConfig = field(default_factory=DepsConfig)
    sast: SastConfig = field(default_factory=SastConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    dast: DastConfig = field(default_factory=DastConfig)
    config: ConfigScannerConfig = field(default_factory=ConfigScannerConfig)
    image: ImageConfig = field(default_factory=ImageConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    severity_overrides: dict[str, dict[str, Severity]] = field(default_factory=dict)
    """Mapping ``{scanner: {rule_id: Severity}}``. Applied after parsing,
    before baseline matching."""

    source: Path | None = None
    """The config file path, or None if defaults were used. Internal use."""


# --- Loading ---------------------------------------------------------------


def find_config_file(start: Path) -> Path | None:
    """Find ``.secscan.toml`` in ``start`` or any ancestor up to the FS root.

    We deliberately do NOT walk past mount points or into user-home unless
    that's the natural ancestor — a single ``resolve()`` is enough; we just
    iterate parents.
    """
    current = start.resolve(strict=False)
    for candidate in (current, *current.parents):
        config = candidate / CONFIG_FILENAME
        if config.is_file():
            return config
    return None


def load_config(scan_root: Path) -> ProjectConfig:
    """Load config rooted at ``scan_root``.

    If no ``.secscan.toml`` exists, returns defaults.
    """
    config_path = find_config_file(scan_root)
    if config_path is None:
        cfg = ProjectConfig()
        # Resolve default baseline path relative to scan_root.
        return _with_resolved_baseline(cfg, scan_root)

    return load_config_file(config_path)


def load_config_file(config_path: Path) -> ProjectConfig:
    """Parse a specific config file path.

    Public mostly for tests; production code typically calls ``load_config``.
    """
    try:
        with config_path.open("rb") as fh:
            raw = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"could not read {config_path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc

    cfg = _parse(raw, config_path)
    return _with_resolved_baseline(cfg, config_path.parent)


def _with_resolved_baseline(cfg: ProjectConfig, anchor: Path) -> ProjectConfig:
    """Resolve baseline.path relative to ``anchor`` if it's relative."""
    baseline = cfg.baseline
    if not baseline.path.is_absolute():
        resolved_path = (anchor / baseline.path).resolve(strict=False)
        baseline = BaselineConfig(
            path=resolved_path,
            default_expiry_days=baseline.default_expiry_days,
        )
    return ProjectConfig(
        fail_on=cfg.fail_on,
        skip=cfg.skip,
        severity_unknown_policy=cfg.severity_unknown_policy,
        deps=cfg.deps,
        sast=cfg.sast,
        secrets=cfg.secrets,
        dast=cfg.dast,
        config=cfg.config,
        image=cfg.image,
        baseline=baseline,
        severity_overrides=cfg.severity_overrides,
        source=cfg.source,
    )


# --- Parsing primitives ----------------------------------------------------

_VALID_SCANNERS = frozenset(
    {"deps", "sast", "secrets", "dast", "config", "image"}
)


def _require_table(value: object, name: str) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a TOML table")
    return value


def _require_int(value: object, name: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{name} must be an integer")
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


def _require_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be a boolean")
    return value


def _require_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _require_str_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list of strings")
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise ConfigError(f"{name}[{i}] must be a string")
        out.append(item)
    return tuple(out)


def _parse_severity(value: object, name: str, *, allow_never: bool = False) -> Severity:
    """Parse a severity name from config.

    ``allow_never`` controls whether the threshold-only sentinel
    ``Severity.NEVER`` ("none") is acceptable. It must be True ONLY for
    ``scan.fail_on``; for ``severity_overrides`` the sentinel would attach
    to actual findings and break invariants downstream (Codex 4th review).
    """
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a severity name string")
    try:
        parsed = Severity.from_name(value)
    except ValueError as exc:
        raise ConfigError(f"{name}: {exc}") from exc
    if parsed == Severity.NEVER and not allow_never:
        raise ConfigError(
            f"{name}: 'none' / NEVER is only valid as a fail-on threshold; "
            f"finding severities must be a concrete level"
        )
    return parsed


def _reject_unknown(table: dict[str, object], known: set[str], section: str) -> None:
    extras = set(table.keys()) - known
    if extras:
        raise ConfigError(f"[{section}] unknown keys: {sorted(extras)}")


# --- Parsers per section ---------------------------------------------------


def _parse(raw: dict[str, object], source: Path) -> ProjectConfig:
    _reject_unknown(
        raw,
        {
            "scan",
            "deps",
            "sast",
            "secrets",
            "dast",
            "config",
            "image",
            "baseline",
            "severity_overrides",
        },
        "root",
    )

    scan = _require_table(raw.get("scan"), "scan")
    deps = _parse_deps(_require_table(raw.get("deps"), "deps"))
    sast = _parse_sast(_require_table(raw.get("sast"), "sast"))
    secrets = _parse_secrets(_require_table(raw.get("secrets"), "secrets"))
    dast = _parse_dast(_require_table(raw.get("dast"), "dast"))
    config_scanner = _parse_config_scanner(
        _require_table(raw.get("config"), "config")
    )
    image_scanner = _parse_image(_require_table(raw.get("image"), "image"))
    baseline = _parse_baseline(_require_table(raw.get("baseline"), "baseline"))
    overrides = _parse_overrides(
        _require_table(raw.get("severity_overrides"), "severity_overrides")
    )

    # [scan] keys
    # Note: ``scan.timeout_seconds`` is intentionally NOT a recognized key.
    # Codex 15th review flagged the previous incarnation as misleading —
    # it was parsed and stored but no code path enforced a whole-run
    # deadline (only per-scanner timeouts are honored). Better to reject
    # the key loudly so users who set it notice it isn't doing anything,
    # than to accept it silently.
    _reject_unknown(
        scan,
        {"fail_on", "skip", "severity_unknown_policy"},
        "scan",
    )
    fail_on = _parse_severity(
        scan.get("fail_on", "high"), "scan.fail_on", allow_never=True
    )
    skip = _require_str_list(scan.get("skip", []), "scan.skip")
    for s in skip:
        if s not in _VALID_SCANNERS:
            raise ConfigError(f"scan.skip: unknown scanner {s!r}")
    unknown_policy = _parse_unknown_policy(
        _require_table(scan.get("severity_unknown_policy"), "scan.severity_unknown_policy")
    )

    return ProjectConfig(
        fail_on=fail_on,
        skip=tuple(skip),
        severity_unknown_policy=unknown_policy,
        deps=deps,
        sast=sast,
        secrets=secrets,
        dast=dast,
        config=config_scanner,
        image=image_scanner,
        baseline=baseline,
        severity_overrides=overrides,
        source=source,
    )


def _parse_unknown_policy(table: dict[str, object]) -> UnknownSeverityPolicy:
    _reject_unknown(
        table,
        {"deps", "sast", "secrets", "dast", "config", "image"},
        "scan.severity_unknown_policy",
    )
    defaults = UnknownSeverityPolicy()
    values: dict[str, str] = {}
    for scanner in _VALID_SCANNERS:
        raw = table.get(scanner, getattr(defaults, scanner))
        s = _require_str(raw, f"scan.severity_unknown_policy.{scanner}")
        if s not in VALID_UNKNOWN_POLICIES:
            raise ConfigError(
                f"scan.severity_unknown_policy.{scanner}: must be one of "
                f"{sorted(VALID_UNKNOWN_POLICIES)}"
            )
        values[scanner] = s
    return UnknownSeverityPolicy(**values)


def _parse_deps(table: dict[str, object]) -> DepsConfig:
    _reject_unknown(
        table,
        {"allow_missing_lockfile", "ignore_dev_dependencies", "timeout_seconds"},
        "deps",
    )
    return DepsConfig(
        allow_missing_lockfile=_require_bool(
            table.get("allow_missing_lockfile", False), "deps.allow_missing_lockfile"
        ),
        ignore_dev_dependencies=_require_bool(
            table.get("ignore_dev_dependencies", False), "deps.ignore_dev_dependencies"
        ),
        timeout_seconds=_require_int(
            table.get("timeout_seconds", DEFAULT_DEPS_TIMEOUT),
            "deps.timeout_seconds",
            minimum=1,
        ),
    )


def _parse_sast(table: dict[str, object]) -> SastConfig:
    _reject_unknown(
        table,
        {"semgrep_config", "timeout_seconds", "allow_unverified_configs"},
        "sast",
    )
    return SastConfig(
        semgrep_config=_require_str_list(
            table.get("semgrep_config", list(DEFAULT_SEMGREP_CONFIG)),
            "sast.semgrep_config",
        ),
        timeout_seconds=_require_int(
            table.get("timeout_seconds", DEFAULT_SAST_TIMEOUT),
            "sast.timeout_seconds",
            minimum=1,
        ),
        allow_unverified_configs=_require_bool(
            table.get("allow_unverified_configs", False),
            "sast.allow_unverified_configs",
        ),
    )


def _parse_secrets(table: dict[str, object]) -> SecretsConfig:
    _reject_unknown(table, {"timeout_seconds"}, "secrets")
    return SecretsConfig(
        timeout_seconds=_require_int(
            table.get("timeout_seconds", DEFAULT_SECRETS_TIMEOUT),
            "secrets.timeout_seconds",
            minimum=1,
        ),
    )


def _parse_config_scanner(table: dict[str, object]) -> ConfigScannerConfig:
    _reject_unknown(table, {"image", "timeout_seconds"}, "config")
    return ConfigScannerConfig(
        image=_require_str(table.get("image", ""), "config.image"),
        timeout_seconds=_require_int(
            table.get("timeout_seconds", DEFAULT_CONFIG_TIMEOUT),
            "config.timeout_seconds",
            minimum=1,
        ),
    )


def _parse_image(table: dict[str, object]) -> ImageConfig:
    """Phase 2-M: parse the ``[image]`` section.

    ``refs`` may be omitted (empty default → opt-in skip). Every
    entry must be a string; the per-ref digest-pin format is
    enforced at scan time by the ImageScanner validators (so that
    a typo in one ref doesn't reject the entire config but does
    surface as a scanner error when that ref is actually scanned).
    """
    _reject_unknown(
        table,
        {"refs", "image", "platform", "cache_volume", "timeout_seconds"},
        "image",
    )
    raw_refs = _require_str_list(table.get("refs", []), "image.refs")
    # Codex Phase 2-M diff review: reject blank entries at config
    # parse time. ``refs = [" "]`` would otherwise pass through to
    # the dispatcher's truthiness check and silently become a
    # zero-target scan exiting 0.
    for i, ref in enumerate(raw_refs):
        if not ref.strip():
            raise ConfigError(
                f"image.refs[{i}] must not be blank — "
                "remove the entry or replace it with a real image ref"
            )
    return ImageConfig(
        refs=raw_refs,
        image=_require_str(table.get("image", ""), "image.image"),
        platform=_require_str(
            table.get("platform", DEFAULT_IMAGE_PLATFORM), "image.platform"
        ),
        cache_volume=_require_str(
            table.get("cache_volume", ""), "image.cache_volume"
        ),
        timeout_seconds=_require_int(
            table.get("timeout_seconds", DEFAULT_IMAGE_TIMEOUT),
            "image.timeout_seconds",
            minimum=1,
        ),
    )


def _parse_dast(table: dict[str, object]) -> DastConfig:
    _reject_unknown(
        table,
        {
            "target",
            "image",
            "ajax_spider",
            "config_file",
            "network_mode",
            "timeout_seconds",
            "mode",
            "auth_headers",
        },
        "dast",
    )
    network_mode = _require_str(
        table.get("network_mode", "bridge"), "dast.network_mode"
    )
    if network_mode not in ("bridge", "host"):
        raise ConfigError(
            f"dast.network_mode: must be 'bridge' or 'host' (got {network_mode!r})"
        )
    mode = _require_str(table.get("mode", "baseline"), "dast.mode")
    if mode not in ("baseline", "active"):
        raise ConfigError(
            f"dast.mode: must be 'baseline' or 'active' (got {mode!r})"
        )
    auth_headers = _require_str_list(
        table.get("auth_headers", []), "dast.auth_headers"
    )
    return DastConfig(
        target=_require_str(table.get("target", ""), "dast.target"),
        image=_require_str(table.get("image", ""), "dast.image"),
        ajax_spider=_require_bool(
            table.get("ajax_spider", False), "dast.ajax_spider"
        ),
        config_file=_require_str(
            table.get("config_file", ""), "dast.config_file"
        ),
        network_mode=network_mode,
        timeout_seconds=_require_int(
            table.get("timeout_seconds", DEFAULT_DAST_TIMEOUT),
            "dast.timeout_seconds",
            minimum=1,
        ),
        mode=mode,
        auth_headers=auth_headers,
    )


def _parse_baseline(table: dict[str, object]) -> BaselineConfig:
    _reject_unknown(table, {"path", "default_expiry_days"}, "baseline")
    path_str = _require_str(table.get("path", DEFAULT_BASELINE_PATH), "baseline.path")
    return BaselineConfig(
        path=Path(path_str),
        default_expiry_days=_require_int(
            table.get("default_expiry_days", DEFAULT_BASELINE_EXPIRY_DAYS),
            "baseline.default_expiry_days",
            minimum=1,
        ),
    )


def _parse_overrides(table: dict[str, object]) -> dict[str, dict[str, Severity]]:
    """Parse [severity_overrides.<scanner>] = { rule_id = "LEVEL", ... }."""
    _reject_unknown(table, set(_VALID_SCANNERS), "severity_overrides")
    out: dict[str, dict[str, Severity]] = {}
    for scanner in _VALID_SCANNERS:
        scanner_table = _require_table(
            table.get(scanner), f"severity_overrides.{scanner}"
        )
        if not scanner_table:
            continue
        out[scanner] = {}
        for rule_id, level in scanner_table.items():
            sev = _parse_severity(level, f"severity_overrides.{scanner}.{rule_id}")
            out[scanner][rule_id] = sev
    return out
