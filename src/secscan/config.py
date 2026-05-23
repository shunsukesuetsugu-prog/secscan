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
DEFAULT_TIMEOUT_SECONDS = 1800
DEFAULT_DEPS_TIMEOUT = 300
DEFAULT_SAST_TIMEOUT = 900
DEFAULT_SECRETS_TIMEOUT = 300
DEFAULT_BASELINE_PATH = ".secscan/baseline.json"
DEFAULT_BASELINE_EXPIRY_DAYS = 90
DEFAULT_SEMGREP_CONFIG: tuple[str, ...] = (
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/owasp-top-ten",
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


@dataclass(frozen=True)
class SecretsConfig:
    timeout_seconds: int = DEFAULT_SECRETS_TIMEOUT
    # redact_secrets is intentionally NOT exposed. Redaction is mandatory.


@dataclass(frozen=True)
class BaselineConfig:
    path: Path = Path(DEFAULT_BASELINE_PATH)
    default_expiry_days: int = DEFAULT_BASELINE_EXPIRY_DAYS


@dataclass(frozen=True)
class ProjectConfig:
    fail_on: Severity = DEFAULT_FAIL_ON
    skip: tuple[str, ...] = ()
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    severity_unknown_policy: UnknownSeverityPolicy = field(default_factory=UnknownSeverityPolicy)
    deps: DepsConfig = field(default_factory=DepsConfig)
    sast: SastConfig = field(default_factory=SastConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
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
        timeout_seconds=cfg.timeout_seconds,
        severity_unknown_policy=cfg.severity_unknown_policy,
        deps=cfg.deps,
        sast=cfg.sast,
        secrets=cfg.secrets,
        baseline=baseline,
        severity_overrides=cfg.severity_overrides,
        source=cfg.source,
    )


# --- Parsing primitives ----------------------------------------------------

_VALID_SCANNERS = frozenset({"deps", "sast", "secrets"})


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
        {"scan", "deps", "sast", "secrets", "baseline", "severity_overrides"},
        "root",
    )

    scan = _require_table(raw.get("scan"), "scan")
    deps = _parse_deps(_require_table(raw.get("deps"), "deps"))
    sast = _parse_sast(_require_table(raw.get("sast"), "sast"))
    secrets = _parse_secrets(_require_table(raw.get("secrets"), "secrets"))
    baseline = _parse_baseline(_require_table(raw.get("baseline"), "baseline"))
    overrides = _parse_overrides(
        _require_table(raw.get("severity_overrides"), "severity_overrides")
    )

    # [scan] keys
    _reject_unknown(
        scan,
        {"fail_on", "skip", "timeout_seconds", "severity_unknown_policy"},
        "scan",
    )
    fail_on = _parse_severity(
        scan.get("fail_on", "high"), "scan.fail_on", allow_never=True
    )
    skip = _require_str_list(scan.get("skip", []), "scan.skip")
    for s in skip:
        if s not in _VALID_SCANNERS:
            raise ConfigError(f"scan.skip: unknown scanner {s!r}")
    timeout = _require_int(
        scan.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
        "scan.timeout_seconds",
        minimum=1,
    )
    unknown_policy = _parse_unknown_policy(
        _require_table(scan.get("severity_unknown_policy"), "scan.severity_unknown_policy")
    )

    return ProjectConfig(
        fail_on=fail_on,
        skip=tuple(skip),
        timeout_seconds=timeout,
        severity_unknown_policy=unknown_policy,
        deps=deps,
        sast=sast,
        secrets=secrets,
        baseline=baseline,
        severity_overrides=overrides,
        source=source,
    )


def _parse_unknown_policy(table: dict[str, object]) -> UnknownSeverityPolicy:
    _reject_unknown(table, {"deps", "sast", "secrets"}, "scan.severity_unknown_policy")
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
    _reject_unknown(table, {"semgrep_config", "timeout_seconds"}, "sast")
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
