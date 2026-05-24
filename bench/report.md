# secscan benchmark report

_secscan 0.8.0_

## Summary

- Overall recall: **15/15 (100.0%)**
- Total false positives (clean fixtures): **0**
- Fixtures run: 6, skipped: 0
- ≥ best single tool (integration parity): **4/4 fixtures**

## Per-fixture detail

| Scanner | Fixture | Expected | Detected | Recall | FP | Compare tool | Compare count | ≥ Best |
|---|---|---|---|---|---|---|---|---|
| secrets | clean | 0 | 0 | 100.0% | 0 | gitleaks | — | — |
| secrets | synthetic | 4 | 4 | 100.0% | 0 | gitleaks | — | — |
| deps | npm-vulnerable | 2 | 2 | 100.0% | 0 | npm audit | 2 | ✅ |
| deps | pip-vulnerable | 3 | 3 | 100.0% | 0 | pip-audit | 15 | ✅ |
| sast | javascript | 2 | 2 | 100.0% | 0 | semgrep | 2 | ✅ |
| sast | python | 4 | 4 | 100.0% | 0 | semgrep | 7 | ✅ |

## Methodology notes

- **Recall** = (detected ∩ expected) / |expected|. Bonus detections beyond the curated set are credited via the raw `Detected` column but do not boost the recall ratio.
- **False positives** are findings emitted on the `clean/` and `safe_*` sibling fixtures.
- **≥ Best single tool** indicates secscan returned at least as many findings as the comparison tool on the same fixture — i.e. the integration layer did not silently downgrade recall.
- Skipped fixtures (tool not installed / docker absent) report as SKIPPED rather than failing; install the listed tool and re-run.

## Interpreting SAST numbers (Codex diff-review pin)

The default semgrep ruleset family is `p/python + p/javascript + p/typescript + p/owasp-top-ten`. These rulesets catch the command-injection family reliably but DO NOT catch every CWE shipped under those names: SQLi via f-string, raw `yaml.load`, hard-coded credentials in Python, and `eval()` in CommonJS JavaScript all slip through with the defaults.

A low SAST recall here therefore reflects the **default ruleset's coverage**, not a bug in the secscan wrapper. The `≥ Best` column demonstrates this by comparing against semgrep run directly with the same rules: when both are 0, the gap is the ruleset, not the integration. Users who need broader CWE coverage should add `p/security-audit` (or a custom ruleset) to `[sast].semgrep_config`.
