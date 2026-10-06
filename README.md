# BlockCap

Blockchain-based capability access control for hierarchical IoT (Cloud /
Fog / Edge) on Hyperledger Besu (QBFT). This repository holds the prototype,
the measurement data, and the IEEE Internet of Things Journal manuscript
and its revision.

## Layout

The public repository contains `code/`, `formal_model_blockCap/` and
`measurements/`. The manuscript (`paper/`), related papers (`references/`),
experiment data (`data/`) and internal revision material (`revision/`,
`reviews/`, `docs/`) are kept locally and are not published.


| Path | Contents |
|---|---|
| `code/` | The prototype. `Node_root/` holds the Flask daemon (`orchestration_service.py`, `orchestrator.py`) and the Solidity contracts (`smart_contract_deployment/contracts/NodeRegistry.sol`). `node-registry-test/` holds the Hardhat contract tests, `scripts/` the topology and experiment drivers, and `tests/` the integration tests. See `code/ReadMe.md` and `code/OPERATIONS.md`. |
| `paper/` | Manuscript (`main.tex`, figures, tables, `data/` behind the plots), plus `contract_audit.md` and `revision_log.md`. |
| `measurements/` | Heterogeneous-testbed raw data (Grafana exports, `trial_1/`) and the original plotting scripts. |
| `data/results/` | Experiment outputs (latency, gas, process events). |
| `data/legacy_results/` | Figures from the original submission. |
| `formal_model_blockCap/` | Alloy 6 model of the System Model (§II), scripts, and bounded model checking results. See its `README.md`. |
| `revision/` | Revision state: `plan.json`, `runbooks/`, `reports/`, `tracker.html`, and `audits/` (data recovery and measurement-script trace). |
| `reviews/` | Independent reviews, consistency audits, and referee-style reports. |
| `docs/phase-0-audit/` | Phase-0 probe scripts and results. |
| `references/` | Related-work papers (PDF). |

`CLAUDE.md` holds the standing revision rules. `PATHS.md` maps the
pre-2026-10-05 directory names that older reports cite to the current ones.

## Running

```bash
cd code
docker compose up --build                     # full stack
../.venv/bin/python -m pytest -m "not integration and not slow"
cd node-registry-test && npx hardhat test     # contract tests
```
