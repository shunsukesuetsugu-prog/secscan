# secscan

Cross-project vulnerability scanning CLI.

> Status: under active development (Phase 1A). Not yet ready for general use.

A single `secscan` command that runs dependency CVE, SAST, and secret detection
across Node/TypeScript and Python projects, normalizing results into one
report and one exit-code policy.

## Goals

- One entry point for vulnerability checks per project (no more
  remembering individual tool invocations).
- Consistent severity normalization and threshold-based exit codes for CI.
- Baseline file for known-issue suppression with audit trail.
- Wraps best-in-class OSS: `semgrep`, `pip-audit`, `gitleaks`, `npm/pnpm audit`.

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| 1A | Common base + `secrets` (gitleaks) | in progress |
| 1B | `deps` (npm / pnpm / pip-audit) | planned |
| 1C | `sast` (semgrep) | planned |
| 1D | `all` + `baseline` finalize + docs | planned |
| 2  | `dast` (OWASP ZAP) | future |

## Development

Requires Python 3.11+.

```sh
pyenv local 3.11.9          # or any 3.11+
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

Detailed docs will land in Phase 1D.
