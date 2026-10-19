# BlockCap

Blockchain-based capability access control for tiered IoT deployments
(Cloud / Fog / Edge, with gateway-proxied endpoints) on Hyperledger Besu
with QBFT consensus.

## Layout

| Path | Contents |
|---|---|
| `code/` | The prototype. `Node_root/` holds the Flask daemon (`orchestration_service.py`, `orchestrator.py`) and the Solidity contracts (`smart_contract_deployment/contracts/NodeRegistry.sol`). `node-registry-test/` holds the Hardhat contract tests, `scripts/` the topology and experiment drivers (including `r2_c05_baselines.py` and `r2_c11_openloop.py`), and `tests/` the integration tests. See `code/ReadMe.md` and `code/OPERATIONS.md`. |
| `code/results/r2_c05/` | Output of the same-hardware baseline measurement. |
| `formal_model_blockCap/` | Alloy 6 model of the system model, scripts, and bounded model checking results. See its `README.md`. |
| `measurements/` | Heterogeneous-testbed raw data (Grafana exports, `trial_1/`) and plotting scripts. |

## Running

```bash
cd code
docker compose up --build                     # full stack
python -m pytest -m "not integration and not slow"
cd node-registry-test && npx hardhat test     # contract tests
```

## Test keys

The key files committed in this repository (`key.priv`, `prefunded_keys.json`)
belong to the local, permissioned test network defined by the genesis files
here (chain ID 1337). They are test fixtures with no value outside that
network. Do not use them on any public network, and generate fresh keys for
any real deployment.
