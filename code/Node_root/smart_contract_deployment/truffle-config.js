const HDWalletProvider = require("@truffle/hdwallet-provider");

// Load private key and RPC URL
const privateKey = "02ad40b4c1f8704b35eb5a73e9287551f995a6647cdd619d2c85439c6464e73b";
const besuRpcUrl = "http://127.0.0.1:8645";

module.exports = {
  networks: {
    besuWallet: {
      provider: () => new HDWalletProvider(privateKey, besuRpcUrl),
      network_id: "*",  // Accept any network ID
      gas:  29000000,  // Increase gas limit
      gasPrice: 0,  // Set Besu to allow 0 gas for private networks
      confirmations: 0,  // Number of confirmations to wait between deployments
      timeoutBlocks: 200,  // Number of blocks before a deployment times out
      skipDryRun: true,  // Skip dry run before migrations
    },
  },
  compilers: {
    solc: {
      // Same solc version and optimizer runs as
      // node-registry-test/hardhat.config.js (the security suite compiles
      // the source in this directory directly) -- but NOT byte-identical
      // bytecode: Truffle 5.11.5 does not honor `viaIR` (confirmed
      // empirically: toggling it here produces no change in output size or
      // hash), while Hardhat's build shrinks by ~5.5KB with it enabled.
      // `runs: 1` is therefore what actually keeps THIS build under the
      // 24576-byte EIP-170 deploy limit (Besu enforces it even on this
      // private, zero-gas-price network -- confirmed by two separate
      // deployment reverts, at 25587 bytes during R07's verification and
      // again at 25250 bytes during 2-3's 2026-09-16 re-verification, both
      // times with the optimizer at runs=20). `viaIR` is left here for
      // documentation of intent even though this toolchain does not act on
      // it; do not rely on it to reduce this build's size.
      version: "0.8.28",
      settings: {
        optimizer: {
          enabled: true,
          runs: 1,
        },
        viaIR: true,
        // The genesis this project deploys to only activates berlinBlock
        // (no london/paris/shanghai fork block/time) -- solc 0.8.28
        // otherwise defaults to a much newer EVM target (cancun) and emits
        // opcodes this chain rejects (confirmed: PUSH0/0x5f caused every
        // transaction to revert with "Invalid opcode" during 2-3's
        // 2026-09-16 re-verification, immediately after fixing the
        // separate EIP-170 size revert). Must match hardhat.config.js.
        evmVersion: "berlin",
      },
    },
  },
};
