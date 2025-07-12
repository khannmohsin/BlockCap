const HDWalletProvider = require("@truffle/hdwallet-provider");

// Load private key and RPC URL
const privateKey = "46aec4d24a59f2c1e3393ff3dd6c8cd40fe256fabce61b7e878220d87b2c3f05";
const besuRpcUrl = "http://10.239.152.40:8545";

module.exports = {
  networks: {
    besuWallet: {
      provider: () => new HDWalletProvider(privateKey, besuRpcUrl),
      network_id: "*",  // Accept any network ID
      gas: 4700000, // Increase gas limit
      gasPrice: 0,  // Set Besu to allow 0 gas for private networks
    },
  },
  compilers: {
    solc: {
      version: "0.8.0", // Explicit Solidity version
    },
  },
};
