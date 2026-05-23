# secscan

Cross-project vulnerability scanning CLI for Web (Node/TypeScript) and Python
projects.

One `secscan` command runs dependency CVE, SAST, and secret-detection
scanners over a project root, normalizes their output into a single report,
and decides pass/fail against a configurable severity threshold. Findings
can be acknowledged via a versioned baseline file with audit metadata.

```sh
secscan all --path .
```

## What's in the box

| Subcommand | Tool wrapped         | What it checks                                      |
| ---------- | -------------------- | --------------------------------------------------- |
| `secrets`  | gitleaks v8+         | hard-coded API keys, tokens, credentials            |
| `deps`     | npm / pnpm / pip-audit | declared dependencies with known CVEs/GHSAs       |
| `sast`     | semgrep              | source-level vulnerability patterns                 |
| `all`      | every registered scanner | secrets + deps + sast in one invocation         |
| `baseline` | (self)               | manage known-issue suppression file                 |

## Install

Requires Python 3.11 or newer.

```sh
# 1. Clone the repo
git clone <repo>
cd secscan

# 2. Create an isolated environment
pyenv local 3.11.9            # or any 3.11+
python -m venv .venv

# 3. Install secscan plus the scanner extras you need:
.venv/bin/pip install -e ".[dev,sast,deps]"
#   - "sast" pulls in semgrep
#   - "deps" pulls in pip-audit
#   - "dev"  pulls in pytest, ruff, mypy
#
# Or, for a minimal install with no Python-side scanners:
# .venv/bin/pip install -e .
```

External binaries — **not** installed by pip:

- **gitleaks** (required for `secscan secrets`): `brew install gitleaks`,
  or download from <https://github.com/gitleaks/gitleaks/releases>.
- **npm** (required for `secscan deps` on npm projects): comes with
  Node.js (≥ v7; v6 is rejected explicitly with a clear error).
- **pnpm** (required for `secscan deps` on pnpm projects): see
  <https://pnpm.io/installation>.

The scanner reports a precise, install-aware error if a required tool is
missing — it never silently exits 0.

## Quick start

```sh
# Scan everything secscan knows about.
secscan all --path .

# One scanner at a time.
secscan secrets --path .
secscan deps    --path .
secscan sast    --path .

# Custom failure threshold (default: high).
secscan deps --fail-on critical

# Disable the baseline for this run.
secscan deps --no-baseline

# Single-line, CI-friendly output.
secscan all --quiet
```

### Exit codes

| Code | Meaning                                                          |
| ---- | ---------------------------------------------------------------- |
| 0    | scan completed; findings at-or-above `--fail-on` were suppressed by baseline or none existed |
| 1    | scan completed; one or more findings crossed the `--fail-on` threshold |
| 2    | scan did **not** complete (tool failure, missing config, missing required lockfile, malformed baseline, etc.) |
| 130  | interrupted by user (SIGINT)                                     |

Codes 1 and 2 never overlap. CI should treat 2 as "inconclusive" — never
as "clean" — because something prevented the scan from running fully.
`secscan all` upgrades exit code from 0 → 2 when a scanner errored or when
a registered scanner wasn't actually run (e.g. missing tool that wasn't
explicitly skipped).

### Severity normalization

All scanners emit findings on the same scale:

`CRITICAL > HIGH > MEDIUM > LOW > INFO > UNKNOWN`

`UNKNOWN` is what we use when an upstream tool gives us no severity at
all — most pip-audit findings, for instance, since pip-audit doesn't
include severity in its JSON output. Whether `UNKNOWN` participates in
the `--fail-on` threshold is configurable per scanner; see
[Configuration](#configuration).

`--fail-on=none` (alias for the sentinel `NEVER`) means "never fail the
build" — useful for purely-informational runs.

## Configuration: `.secscan.toml`

Drop a `.secscan.toml` at the project root. secscan also walks parents.

```toml
[scan]
fail_on = "high"               # critical | high | medium | low | none
skip = []                      # e.g. ["sast"] to skip a scanner in `all`
# Per-scanner timeouts live under [deps] / [sast] / [secrets] — there is
# no whole-run timeout in MVP.

[scan.severity_unknown_policy]
# How findings with severity=UNKNOWN are treated, per scanner:
#   "warn"   – counted in display but never cross the threshold
#   "fail"   – treated as the fail-on threshold (i.e. they DO cross)
#   "ignore" – still displayed, but excluded from threshold check
deps    = "warn"
sast    = "warn"
secrets = "fail"

[deps]
allow_missing_lockfile  = false  # error when npm/pnpm has no lockfile
ignore_dev_dependencies = false  # adds --omit=dev (npm) / --prod (pnpm)
timeout_seconds         = 300

[sast]
# Each entry becomes a separate `--config` flag to semgrep.
# Default-safe set: registry shorthand (p/..., r/...) AND paths under
# the scan root. Any other value (arbitrary URL, out-of-tree absolute
# path) is REJECTED unless `allow_unverified_configs = true` below.
semgrep_config = ["p/python", "p/javascript", "p/typescript", "p/owasp-top-ten"]
allow_unverified_configs = false  # opt-in for arbitrary URLs / outside paths
timeout_seconds = 900

[secrets]
timeout_seconds = 300
# Note: secret redaction is mandatory; there is no opt-out switch.

[baseline]
path = ".secscan/baseline.json"  # resolved relative to THIS file's dir
default_expiry_days = 90

# Per-scanner severity overrides for noisy/critical rules.
# Keys are rule_ids; values follow the severity scale (no `none`).
[severity_overrides.secrets]
"aws-access-token" = "CRITICAL"
```

All keys are typed and unknown keys raise an error. A typo'd
`severity_overide` (missing `r`) is rejected loudly rather than
silently doing nothing.

## Baseline workflow

Findings you decided to accept are written to a JSON baseline:

```sh
# Acknowledge every current finding (use sparingly).
secscan baseline accept --all --reason "initial baseline, tracked in TICKET-123"

# Acknowledge specific findings by fingerprint.
secscan baseline accept --fingerprint abc123 --fingerprint def456 \
    --reason "false positive: confirmed test fixture"

# List current entries.
secscan baseline list

# Remove expired entries (the file is never auto-pruned).
secscan baseline prune
```

Each baseline entry records `accepted_by`, `reason` (non-empty), `added_at`,
`expires_at`, `secscan_version`, and a `raw_fingerprint` when the upstream
tool provided one. The CLI refuses to:

- write the baseline in CI (`SECSCAN_CI=1`).
- accept any finding when **any scanner errored** during the scan — a
  partial scan must not produce a baseline that hides real findings.
- accept fingerprints that aren't in the current scan output.

Expired entries do not auto-suppress — they re-surface as warnings on the
next run so the lapse is loud, not silent.

## CI integration

GitHub Actions example:

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: "3.11"

- name: Install secscan + scanners
  run: |
    pip install -e ".[sast,deps]"
    brew install gitleaks  # macOS runners

- name: Run secscan
  env:
    SECSCAN_CI: "1"  # blocks `baseline accept` from running
  run: secscan all --quiet --fail-on high
```

Exit 1 → step fails. Exit 2 → step fails (and the log shows the
`partial scan` warning so the operator knows why).

## Security posture

A few invariants worth knowing about if you're auditing the tool itself:

- **Subprocess execution.** Every external tool is invoked via
  `subprocess.run(shell=False)` with an argv list — no shell interpolation.
- **Secrets never enter secscan's address space.** gitleaks is started
  with `--redact=100`. The `Finding.raw` payload force-overrides
  `Secret`/`Match` fields with `[REDACTED]` even if the upstream tool
  somehow returned them unredacted. Author / Email / Commit / Message
  fields are dropped via a whitelist.
- **Scanner output paths are re-verified.** A scanner that reports
  `/etc/passwd` or `../../etc/passwd` has the path stripped before any
  Finding is rendered.
- **stderr / messages are redacted before truncation.** AWS keys,
  GitHub tokens, JWTs, npm `_authToken=` lines, URL basic-auth credentials,
  PyPI tokens, and `pip index-url=` lines are scrubbed.
- **`semgrep_config` is gated.** Only registry shorthand (`p/`, `r/`) and
  paths under the scan root are accepted by default. Arbitrary URLs and
  out-of-tree absolute paths require explicit opt-in
  (`[sast].allow_unverified_configs = true`). An untrusted PR that
  modifies `.secscan.toml` cannot point semgrep at a malicious ruleset.
- **Baseline tamper resistance.** Malformed baseline files raise
  `BaselineError`, exit 2; a corrupt baseline cannot silently disable
  suppression. Entries match on the full `(fingerprint, scanner, rule_id)`
  tuple, so a hash collision across scanners cannot silence the wrong
  finding.

For a deeper look, the source modules carry inline rationale tied to the
specific Codex review iteration that motivated each invariant.

## Status

| Phase | Scope                                              | Status                  |
| ----- | -------------------------------------------------- | ----------------------- |
| 1A    | Common base + `secrets` (gitleaks)                 | done                    |
| 1B    | `deps` (npm / pnpm / pip-audit)                    | done                    |
| 1C    | `sast` (semgrep)                                   | done                    |
| 1D    | docs + final review                                | in progress             |
| 2     | DAST (OWASP ZAP), monorepo / workspaces, SARIF out | future                  |

## Development

```sh
.venv/bin/pytest               # 354 unit tests + 2 integration (skipped without the binaries)
.venv/bin/ruff check src/ tests/
.venv/bin/mypy --strict src/secscan
```

Integration tests against real `gitleaks` / `semgrep` are gated by
`pytest.mark.integration` and skip cleanly when the binary is not on
PATH. They produce a useful smoke check during development; CI may
choose to install the tools and run them, or skip.

## Known limitations (MVP)

- Single-project layout only. Monorepos / workspaces (pnpm-workspaces,
  uv workspaces, etc.) are deferred to Phase 2 — Discovery emits a
  warning when nested manifests are detected.
- No JSON / SARIF output yet. The terminal report is the only format.
- No DAST yet — `secscan dast` is reserved for Phase 2.
- npm v6 audit output is explicitly **not** parsed; the scanner rejects
  it with an instructive error telling the user to upgrade to npm v7+.
- pip-audit cannot consume `uv.lock` / `pdm.lock` directly. The scanner
  errors out with a hint to `uv export` / `pdm export` to
  requirements.txt first.

## License

MIT
