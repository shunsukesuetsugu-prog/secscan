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
| `deps`     | npm / pnpm / yarn / pip-audit | declared dependencies with known CVEs/GHSAs |
| `sast`     | semgrep              | source-level vulnerability patterns                 |
| `dast`     | OWASP ZAP (Docker)   | live HTTP target probing — baseline + active (Phase 2-J) |
| `config`   | Trivy (Docker)       | IaC: k8s manifests, Terraform, Dockerfile, Helm (Phase 2-L) |
| `image`    | Trivy (Docker, image mode) | container image CVEs — OS pkg + language pkg vulns (Phase 2-M) |
| `all`      | every registered scanner | secrets + deps + sast + config (and dast/image when their targets are configured) |
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

# Machine-readable output formats.
secscan all --format json                   # secscan-json v1 to stdout
secscan all --format sarif > scan.sarif     # SARIF 2.1.0 to file via shell
secscan all --format sarif --output scan.sarif

# Include baseline-suppressed findings in SARIF (default: excluded).
secscan all --format sarif --sarif-include-suppressed
```

### Output formats

| Format  | Use case                                                                |
| ------- | ----------------------------------------------------------------------- |
| `text`  | Default. Human-readable terminal report. Color when stdout is a TTY.    |
| `json`  | secscan-json v1. Stable structured schema with counts, errors, suppressed. |
| `sarif` | SARIF 2.1.0 with per-scanner runs. Ready for GitHub Code Scanning upload. |

`--quiet` is text-only; combining it with `--format=json` or `--format=sarif`
is a CLI error (the structured formats already produce single-document
output that's safe to parse).

SARIF caveats worth knowing:

- One `run` per scanner that actually executed. Skipped scanners are **not**
  emitted as empty success runs — uploading those would mark previously-
  reported alerts on the missing scanner as fixed.
- Baseline-suppressed findings are **excluded** by default (GitHub Code
  Scanning doesn't reliably honor SARIF suppressions). Opt in with
  `--sarif-include-suppressed` for archive / non-GitHub viewers.
- `Finding.raw` and `Finding.raw_fingerprint` are **never** in the output
  (the latter can embed upstream-tool paths that bypass secscan's
  path-stripping).
- No source `snippet` or artifact `contents` is emitted.
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

## DAST (OWASP ZAP)

The `dast` subcommand runs an OWASP ZAP baseline scan against a live
HTTP target via Docker. It is **opt-in**: `secscan all` only includes
DAST when `dast.target` is set in `.secscan.toml` (or `--target` was
passed on the CLI).

```sh
# Smoke a staging deployment.
secscan dast \
  --target https://staging.example.com/ \
  --zap-image zaproxy/zap-stable@sha256:<verified-digest> \
  --format sarif --output zap.sarif
```

Required CLI flags / config:

| Flag                  | Equivalent config key   | Purpose                                              |
| --------------------- | ----------------------- | ---------------------------------------------------- |
| `--target <URL>`      | `dast.target`           | HTTP/HTTPS URL to probe (mandatory).                 |
| `--zap-image <ref>`   | `dast.image`            | OCI image ref **with `@sha256:` digest pinning**.    |
| `--ajax-spider`       | `dast.ajax_spider`      | Enable ZAP's AJAX spider (slower; JS-heavy targets). |
| `--zap-config-file`   | `dast.config_file`      | ZAP context file path **inside the container**.      |
| `--zap-network`       | `dast.network_mode`     | `bridge` (default) or `host`.                        |
| `--auth-header`       | `dast.auth_headers`     | HTTP header injected into every ZAP request (Phase 2-K, repeatable). |

Hard requirements baked into the implementation:

- **Image digest pinning is mandatory.** An image without
  `@sha256:<64 hex>` is rejected before docker is invoked, and a
  leading `-` is also rejected to make argv injection structurally
  impossible.
- **Argv shape is fixed.** `docker run … -- <image> <cmd>` —
  the `--` separator is always present so the image value cannot be
  flag-interpreted under any future refactor.
- **No host leakage in external output.** SARIF / JSON / text reports
  emit a normalized relative URI `dast/<urlencoded-path>`; the target
  host is never echoed into `location.uri`.
- **`--cap-drop=ALL` + `--network=bridge` by default.** Operators can
  opt into `--network=host` explicitly when targeting a service that
  is only bound to the host namespace.
- **Findings are deduped on `(pluginid, path, query-keys, param)`** and
  carry a coarse `(pluginid, path)` alias, so a single
  `baseline accept` suppresses both the `param`-bearing and
  `param`-less variants of the same advisory.

### Authenticated DAST (Phase 2-K)

Many real-world bugs only surface behind a login. `--auth-header`
forwards a static HTTP header — typically a JWT bearer token your
test harness obtained out of band — into **every** request ZAP sends:

```sh
# 1. Obtain a token from your auth flow (curl / your test rig).
TOKEN=$(curl -s -X POST https://staging.example.com/login \
  -H 'content-type: application/json' \
  -d '{"email":"qa@example.com","password":"…"}' | jq -r .token)

# 2. Hand it to secscan dast.
secscan dast \
  --target https://staging.example.com/ \
  --zap-image zaproxy/zap-stable@sha256:<verified-digest> \
  --auth-header "Authorization: Bearer $TOKEN"
```

`--auth-header` is repeatable — pass it multiple times for multi-header
auth schemes (e.g. `Authorization: Bearer …` + `X-Tenant: acme`).
Internally each header becomes one entry in ZAP's
[`replacer.full_list`](https://www.zaproxy.org/docs/desktop/addons/replacer/)
config; secscan single-quotes every `key=value` pair so values
containing spaces (every Bearer token) survive ZAP's whitespace
tokenisation.

Header value rules (enforced by the validator, all rejections
produce a clear `DastInputError` at argv-build time):

- **Must contain `:`** between name and value.
- **Name** must be a [RFC 7230](https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6)
  token — `=`, `,`, `(` and other ZAP `-z` syntax sigils are
  rejected so the value cannot break out of the replacer key/value
  position.
- **Value** must be non-empty, printable, and free of CR / LF
  (classic header smuggling defence) and single quotes (we use
  single quotes to wrap the `key=value` pair, so an embedded `'`
  would close the wrap early).
- **`--auth-header` values flow through secscan's redactor in
  logs**; the raw token is never written to stdout or the report.

### ZAP image digest rotation

The pinned default in
`src/secscan/scanners/dast/_pinned.py` ships with an all-zero
digest sentinel — the scanner will run, but Docker will refuse to
pull the image. Operators are expected to pin a verified digest the
first time they enable DAST:

```sh
docker pull zaproxy/zap-stable:2.15.0
docker inspect --format='{{index .RepoDigests 0}}' zaproxy/zap-stable:2.15.0
# zaproxy/zap-stable@sha256:<digest>
```

Set the verified digest under `[dast].image` in `.secscan.toml` (or
pass it via `--zap-image`).

## Container image scan (Trivy, Phase 2-M)

`secscan image` scans one or more **built** OCI images for known
CVEs in OS packages (alpine/debian apt/apk/yum DBs) AND in language
packages embedded in the image (npm/pip/gem/etc.). It catches the
class of vulnerability that the source-tree scanners
(`deps`/`sast`/`secrets`) cannot see — for example, an old `openssl`
shipped in your base image even though your `requirements.txt`
itself is clean.

```sh
# Scan a single image. Digest pin (@sha256:...) is mandatory.
secscan image \
  --image alpine@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98 \
  --format sarif --output image.sarif

# Or via config + secscan all
# .secscan.toml:
# [image]
# refs = [
#   "alpine@sha256:451eee...",
#   "my-corp/api@sha256:abcdef...",
# ]
# platform = "linux/amd64"   # default
```

Required CLI flags / config:

| Flag                    | Equivalent config key   | Purpose                                          |
| ----------------------- | ----------------------- | ------------------------------------------------ |
| `--image <ref>`         | `[image].refs`          | target OCI image (repeatable). Digest pinning is mandatory. |
| `--trivy-image <ref>`   | `[image].image`         | OCI image ref of the Trivy *scanner* container.  |
| `--platform <os/arch>`  | `[image].platform`      | docker `--platform` (default `linux/amd64`).     |

Hard requirements baked into the implementation:

- **Both image refs are digest-pinned.** The Trivy scanner image
  AND every target image must be `<repo>[:tag]@sha256:<64 hex>`.
  A bare `alpine:3.10` is rejected with a clear error before
  docker is invoked. This is the same posture as DAST (Phase 2-D)
  and config (Phase 2-L) — secscan never invokes docker against
  a mutable tag.
- **`--platform` is forced on both layers** (docker + Trivy CLI).
  Without an explicit platform, a multi-arch OCI index digest
  resolves to different per-arch manifests on different hosts,
  silently changing what got scanned. We default to
  `linux/amd64`; override per-deployment via config.
- **`--cap-drop=ALL --security-opt=no-new-privileges` always.**
- **`--network=bridge` is mandatory here.** Trivy must reach the
  registry to pull the target image; `--network=none` is
  impossible in image mode. The DAST scanner made the same
  trade-off. `host` networking is NOT allowed.
- **Opt-in like DAST.** `secscan all` only runs the image scanner
  when `[image].refs` is non-empty (or `--image` is on the CLI).
  `secscan image` with zero refs fails loud (exit 2) rather than
  exiting 0 with no findings — a false-green that would let CI
  report "image scan clean" when nothing was actually scanned.
- **Findings are deduped on `(CVE-ID, package, version, location)`.**
  Scanning two images that ship the same vulnerable package
  produces ONE finding, not two — so a baseline accept on the
  CVE silences it across all targets at once.

### Deterministic vs online Trivy DB

By default, every `secscan image` invocation pulls the latest Trivy
vulnerability DB from ghcr.io. For reproducible bench runs (and any
offline CI runner), `bench/run.py --image-bench` pre-seeds a named
docker volume with the DB once and then mounts it read-only +
`--skip-db-update` for each scan. The end-user CLI doesn't expose a
cache-volume flag — it's a bench/CI plumbing concern, not an
everyday operator setting.

## Detection-rate benchmark

`bench/run.py` measures how much of a curated known-vulnerable
corpus secscan detects and how it compares to single-tool baselines.

```sh
.venv/bin/python bench/run.py            # runs every available scanner
```

Latest results on this machine (re-run locally for an up-to-date
snapshot; see `bench/report.md` for the full table):

### Curated fixtures (in-sample — we author these, so 100% is the
expected ceiling)

| Scanner | Fixture | Recall | FP | vs single tool |
|---|---|---|---|---|
| deps    | npm-vulnerable | 100% | 0 | = npm audit ✅ |
| deps    | pip-vulnerable | 100% | 0 | = pip-audit (deduped) ✅ |
| sast    | python | 100% | 0 | ≥ semgrep ✅ |
| sast    | javascript | 100% | 0 | = semgrep ✅ |
| secrets | synthetic | 100% | 0 | = gitleaks ✅ |
| dast    | juice-shop | 100% | 0 | = zap-baseline ✅ |

### External benchmarks (third-party, out-of-sample — added in
Phase 2-I to surface over-fit)

| Scanner | Fixture | Recall | FP | Notes |
|---|---|---|---|---|
| dast | webgoat | 100% (6/6) | 0 | second DAST target validates lifecycle generalises |
| external/secrets | gitleaks-corpus | 100% (2/2) | 0 | parity with gitleaks on its own testdata |
| external/sast | pygoat | 100% (9/9) | 0 | Python OWASP Top 10 |
| external/sast | nodegoat | 80% (8/10) | 0 | JS XSS (.ejs templates) + broken auth still escape |

**Overall: 45/47 = 95.7%** across **11 benchmarks**, false
positives: **0**, ≥ best single tool: **4/4**. Run with
`--dast --external` to include all third-party benchmarks
(requires docker + git; adds 5-10 minutes for the
clone-and-scan cycle).

The 80% on NodeGoat is the headline honest number — secscan
catches 8 of 10 expected CWE categories on a benchmark we did
NOT design or tune to. The two misses (CWE-79 in .ejs
templates, CWE-287 broken authentication) reflect genuine
limits of static analysis on those patterns, not gaps in the
scanner integration layer.

Phase 2-F + 2-G tuning (post-initial benchmark) lifted recall
from 54.5% → 86.7% → **100%** by:

1. **`p/default` ruleset** added to the default semgrep family
   (JavaScript SAST 0% → 100%; Python SAST 25% → 50%).
2. **gitleaks tempfile fix** — switched from
   `--report-path=/dev/stdout` (which gitleaks refuses on macOS)
   to a 0700 tempfile the scanner manages with 0600 chmod +
   try/finally cleanup. A real cross-platform bug the bench
   surfaced.
3. **pip-audit comparison dedup** by `(package, advisory_id)`
   (pip-audit ships some advisories twice from different source
   DBs; secscan dedups, so a fair comparison must too).
4. **Bundled secscan rules** (`secscan:extra` sentinel) shipping
   under `src/secscan/rules/` — Python `yaml.load` without
   SafeLoader (CWE-502) and hard-coded credentials in named
   variables (CWE-798), the two CWE categories the public
   registry packs do not cover. The sentinel passes the
   `_reject_unsafe_configs` safety gate (it points at our own
   code, not user input) but is otherwise treated like any
   path-based ruleset. Lifted Python SAST recall 50% → **100%**.

What's still scope-limited rather than a recall miss:

- **Real-codebase FP rate**: the curated `safe_*` borderline
  fixtures stay clean, but they don't represent the full
  diversity of real source trees. Adding `p/security-audit` for
  even broader CWE coverage is opt-in via `[sast].semgrep_config`.

Phase 2-H added the DAST measurement (`bench/run.py --dast`).
Lifecycle: bring up OWASP Juice Shop on `127.0.0.1:3000` →
`secscan dast` internally orchestrates a docker volume + Alpine
helper chown + zap-baseline.py scan + report extraction → compare
detected ZAP pluginids against `bench/fixtures/dast/juice-shop/
expected.json`. The `--dast` flag is opt-in because the full
lifecycle takes 2-4 minutes; the fast `bench/run.py` (no flag)
skips it.

See `bench/README.md` for the full methodology, retraction policy,
and how to add new fixtures.

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
| 1D    | docs + final review                                | done (v0.1.0)           |
| 2-A   | JSON / SARIF output                                | done (v0.2.0)           |
| 2-B   | monorepo / workspaces (pnpm + npm)                 | done (v0.3.0)           |
| 2-C   | uv per-member audit + Yarn Berry workspaces        | done (v0.4.0)           |
| 2-D   | DAST (OWASP ZAP, Docker)                           | done (v0.5.0)           |
| 2-E   | detection-rate benchmark (bench/)                  | done (v0.6.0)           |
| 2-F   | tune defaults to improve bench recall (54.5% → 86.7%) | done (v0.7.0)        |
| 2-G   | bundled secscan semgrep rules (recall 86.7% → 100%) | done (v0.8.0)          |
| 2-H   | DAST 自動計測 (Juice Shop + docker volume lifecycle) | done (v0.9.0)         |
| 2-I   | 外部 benchmark (NodeGoat / PyGoat / WebGoat / gitleaks corpus) | done (v0.10.0) |
| 2-J   | ZAP active scan opt-in (`--mode=active` + `--dast-active`) | done (v0.11.0)    |
| 2-L   | Trivy config scan (IaC/k8s/Docker/Helm)             | done (v0.12.0)        |
| 2-K   | ZAP auth-flow via HTTP header injection (`--auth-header`)  | done (v0.13.0) |
| 2-M   | container image CVE scan (`secscan image`, Trivy image mode)   | done (v0.14.0) |

## Development

```sh
.venv/bin/pytest               # 648 unit tests + 2 integration (skipped without the binaries)
.venv/bin/ruff check src/ tests/ bench/
.venv/bin/mypy --strict src/secscan
.venv/bin/python bench/run.py  # detection-rate benchmark (see bench/README.md)
```

Integration tests against real `gitleaks` / `semgrep` are gated by
`pytest.mark.integration` and skip cleanly when the binary is not on
PATH. They produce a useful smoke check during development; CI may
choose to install the tools and run them, or skip.

## Monorepos / workspaces

`secscan deps` understands the four most-common JavaScript / Python
workspace configurations and audits each member separately:

| Workspace format | Detection                                                         | Per-member audit            |
| ---------------- | ----------------------------------------------------------------- | --------------------------- |
| **pnpm**         | `pnpm-workspace.yaml` (`packages:` glob, `!` excludes supported)  | `pnpm audit --filter <name>` |
| **npm**          | `package.json#workspaces` (array or `{packages: [...]}`)          | `npm audit --workspace <name>` |
| **uv** (Python)  | `[tool.uv.workspace] members` + `exclude` in `pyproject.toml`      | `uv export --locked --no-emit-local --package <name>` → pip-audit on the resulting requirements file (Phase 2-C-1) |
| **yarn (Berry)** | `package.json#packageManager: "yarn@2+"` / `__metadata:` in yarn.lock / `.yarnrc.yml` | `yarn workspace <name> npm audit --json --recursive` (Phase 2-C-2) |
| **yarn (Classic)** | `# yarn lockfile v1` header                                      | **unsupported**, warning emitted (upgrade to Berry or switch to npm/pnpm) |

Properties that make this safe for monorepos:

- The audit always runs from the **repo root** so the authoritative root
  lockfile is used; `--workspace` / `--filter` scope the result to one
  member.
- Each member gets a **distinct fingerprint** (`deps-ws:` prefix +
  member name). The same `lodash` advisory in `packages/api` and
  `packages/web` produces two separate baseline entries — accepting one
  does NOT silence the other.
- File paths in findings are rewritten to **repo-root-relative** form
  (e.g. `packages/api/src/leak.py`), so reports stay consistent
  regardless of which member the scanner ran in.
- Symlinked workspace members, glob patterns with `..` / absolute
  paths / URI schemes, and member `name` strings containing pnpm
  selector grammar (`!`, `*`, `^`, `~`, ...) are all refused with a
  warning rather than included.
- An empty or malformed workspace config does NOT silently disable the
  repo-root scan — single-project deps detection still runs.
- Workspace member counts above 50 emit an informational warning; above
  100 the list is truncated with a separate warning.

Secrets and SAST scanners are not workspace-aware; they always scan the
whole repo root as a single unit (file content doesn't follow
ecosystem boundaries).

### Cross-tool baseline compatibility

If you migrate between package managers (e.g. yarn → pnpm, npm → yarn
Berry), an existing baseline keeps working: secscan picks the canonical
advisory identifier in the same order across npm / pnpm / yarn —
**GHSA → CVE → URL → numeric id** — so the same advisory in any of
those reports hashes to the same fingerprint.

### Threat model note for Yarn Berry

`.yarnrc.yml` may set `yarnPath` to an arbitrary JavaScript file that
yarn then executes. secscan treats the `yarn` CLI (and the binary it
points at) as trusted, same way it trusts `npm`, `pnpm`, `pip-audit`,
and `semgrep`. **Do not** run `secscan deps` against an untrusted
project root.

## Known limitations

- No DAST yet — `secscan dast` is reserved for a future release.
- npm v6 audit output is explicitly **not** parsed; the scanner rejects
  it with an instructive error telling the user to upgrade to npm v7+.
- pip-audit cannot consume `uv.lock` / `pdm.lock` directly. The scanner
  errors out with a hint to `uv export` / `pdm export` to
  requirements.txt first. (uv workspaces are handled per member
  automatically via `uv export --locked`.)
- Yarn Classic (v1) is unsupported; upgrade to Yarn Berry (v2+) or
  switch to pnpm / npm.

## License

MIT
