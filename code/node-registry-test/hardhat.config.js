require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    // Same solc version and optimizer runs as the default deployment
    // config (Node_root/smart_contract_deployment/truffle-config.js).
    // NOT byte-identical bytecode: Truffle 5.11.5 does not honor `viaIR`
    // (confirmed empirically -- toggling it produces no size change under
    // Truffle's compile, while it saves ~5.5KB here under Hardhat) and the
    // two tools default to different EVM targets (Hardhat: paris, Truffle:
    // cancun). `runs: 1` is what actually keeps BOTH toolchains' builds
    // under the 24576-byte EIP-170 limit; viaIR is kept enabled here since
    // it costs nothing and further reduces this build's size, but is not
    // something Truffle's build can be relied on to replicate. Before
    // every test run, `sync-contract-test-source.js` materializes a
    // checked generated copy of the authoritative source.
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1,
      },
      viaIR: true,
      // Must match truffle-config.js: the deployed genesis only activates
      // berlinBlock, so solc's newer default EVM target (cancun) emits
      // opcodes (PUSH0) that chain rejects at runtime.
      evmVersion: "berlin",
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};
