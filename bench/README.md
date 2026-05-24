# secscan benchmark suite

Measures how much of a known-vulnerable corpus secscan detects, and
compares the count of findings against single-tool baselines (`npm
audit`, `pip-audit`, `gitleaks`, `semgrep`) for parity.

## Run

```sh
.venv/bin/python bench/run.py                # all available scanners
.venv/bin/python bench/run.py --only deps    # subset
.venv/bin/python bench/run.py --dast         # include DAST (requires docker + juice-shop fixture)
.venv/bin/python bench/run.py --dast-authflow  # Phase 2-K: authenticated DAST (logs in, then re-scans with --auth-header)
.venv/bin/python bench/run.py --image-bench    # Phase 2-M: container image CVE scan (alpine:3.10 vulnerable + alpine:3.21 clean)
.venv/bin/python bench/run.py --sbom-bench     # Phase 2-N: SBOM-based CVE scan via Syft+Grype (committed CycloneDX SBOM fixtures)
```

Outputs are committed under `bench/report.md` (human) and
`bench/report.json` (machine). Re-run after upgrading any wrapped
external tool to detect coverage drift.

## What's measured

- **Recall**: `(detected ∩ expected) / |expected|` per fixture. The
  curated `expected_findings` set is a **minimum bar** — bonus
  detections in the raw count are credited but do not boost recall
  beyond 100%.
- **False positives**: findings that hit `clean/` or `safe_*`
  siblings. Border-case clean fixtures (e.g.
  `safe_subprocess.py`, `aws_lookalike.txt`) intentionally use
  patterns close to the vulnerable shape so FP=0 is informative.
- **≥ Best single tool**: secscan's RAW finding count vs the
  comparison tool's. This is an **integration parity** check, not
  a "secscan wins" check — secscan aggregates the same tool the
  comparison invokes directly, so the goal is parity, not lead.

## Fixtures

```
bench/fixtures/
├── deps/        — known-vulnerable lockfiles per ecosystem
├── secrets/     — synthetic credentials (SHA-256-pinned) + clean/border
├── sast/        — per-language CWE fixtures + clean/border
└── dast/        — Docker-deployed targets (e.g. OWASP Juice Shop)
```

Each fixture directory has an `expected.json` describing what should
be detected and how the matcher should compare.

## Security: synthetic-secret manifest

`bench/fixtures/secrets/synthetic/_manifest.json` records the
SHA-256 hash, source documentation, and explicit invalidity reason
for every secret-shaped fixture. `bench/run.py` refuses to execute
if any hash diverges — a divergence might mean a maintainer
accidentally replaced a synthetic placeholder with a real
credential.

To add a new synthetic secret:

1. Confirm the candidate value is **structurally invalid** (e.g.
   official "example" credentials, all-zero bodies, deliberately
   bad checksums).
2. Document why in the manifest's `invalidity_reason`.
3. Compute the SHA-256 (`shasum -a 256 <file>`) and add the entry.
4. Commit both file and manifest together.

## Policy-driven checks (`policy_driven_check_ids`)

The `config` scanner (Phase 2-L, Trivy) ships some checks whose
firing depends on an **organisation-specific policy bundle**
rather than on the manifest itself. The canonical example is
`KSV-0125 "Restrict container images to trusted registries"`:
Trivy has no default allowlist, so it always fires until the
operator configures their org's trusted registry set.

For benchmark purposes these checks would inflate the false-
positive count on `clean/` fixtures even though the fixture is
itself correctly hardened. Each `clean/expected.json` may
declare a `policy_driven_check_ids` array; the bench runner
counts those firings under the report's raw count but excludes
them from the headline FP number. This is a documented
allowlist, not a silent suppression — every entry is visible in
`expected.json` so a reader can audit what was excluded and why.

## Retraction policy

The advisory databases (npm advisories, PyPI/OSV, GitHub Advisory
Database) can retract or rename advisories. When that happens, a
fixture may show recall=0 for a previously-expected entry because
the advisory no longer matches.

Process:

1. The runner emits a `retracted_or_renamed?` warning in the report
   when an expected entry has zero detections AND the comparison
   tool also returns zero — the signal is "the advisory is gone,
   not the scanner regressed."
2. The maintainer verifies via the upstream advisory DB.
3. The fixture's `expected.json` is updated with a **different**
   stable advisory in the same package (don't delete — git history
   is the audit trail).

## CI integration

The bench is **not** part of the unit test suite (heavy + requires
multiple external tools). Recommended CI shape:

- Unit tests (`pytest`): run on every PR (~2 seconds).
- Bench (`make bench`): run on push to `main` and once per week
  on a schedule.
- The bench should **not** gate PR merges — it surfaces drift, not
  regressions in the scanner code itself.
