# BlockCap contract security tests

Before each test, the harness copies the authoritative deployment source from
`../Node_root/smart_contract_deployment/contracts/NodeRegistry.sol` into its
generated test input. Do not hand-edit a local `NodeRegistry.sol`; the sync
step replaces it and tests would otherwise be able to validate stale code.

Keep `hardhat.config.js` aligned with
`Node_root/smart_contract_deployment/truffle-config.js`.
