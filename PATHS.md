# Path map (restructure of 2026-10-05)

Reports, reviews and audits written before 2026-10-05 cite the old paths.
They are historical records and were not edited; use this table to resolve
them.

| Old path | New path |
|---|---|
| `BlockCap_code/` | `code/` |
| `BlockCap/` (also cited as `BlockCap_paper/`) | `paper/` |
| `Node_measurements/` | `measurements/` |
| `results/` (repo root) | `data/results/` |
| `BlockCap_results/` | `data/legacy_results/` |
| `BlockCap_related_papers/` | `references/` |
| `Claude outputs/` | `reviews/claude-referee-reports/` |
| `data_recovery_report.md` | `revision/audits/data_recovery_report.md` |
| `measurement_script_trace.md` | `revision/audits/measurement_script_trace.md` |

Paths inside `code/` (e.g. `code/results/`, `code/runtime/generated/`) are
unchanged relative to the code root.

## Removed on 2026-10-05

Deleted at the owner's request; reports citing them can no longer be
re-checked against the files.

- `code/runtime/generated/acm-results/` (2026-04-28)
- `code/runtime/generated/single-latency/`, `single-latency-final/`,
  `single-latency-final2/`, `single-latency-final3/` (2026-09-07)
- Dead stubs: `node-registry-test/test/interact.cli.test.js` (empty) and its
  `test:interact` npm script, `node-registry-test/ignition/modules/Lock.js`
  (Hardhat sample), `Node_root/tests/test_existing_*.py` (re-exports of
  tests already collected from `Node_root/scripts/`)
- Python/OS caches (`__pycache__/`, `.DS_Store`, `.pytest_cache/`)

## Known stale references (left as-is)

- `paper/main.tex` line 27 mentions `Node_measurements/*.py` in a LaTeX
  comment. Manuscript edits require a runbook step.
- `measurements/*.py` hard-code `/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/...`.
  These paths were already broken before the restructure. The scripts are
  audited provenance, so they were not edited.
