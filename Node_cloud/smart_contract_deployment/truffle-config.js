const HDWalletProvider = require("@truffle/hdwallet-provider");

// Load private key and RPC URL
const privateKey = "c648787b4e56655159b3938f41c991300177e70349aa9b1d478b57bd88808c36";
const besuRpcUrl = "http://127.0.0.1:8545";

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
