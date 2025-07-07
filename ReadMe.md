# DTEA: Distributed Trust Enforcement Architecture for Distributed IoT Infrastructure

## Overview

**DTEA** is a layered, blockchain-based security architecture designed for decentralized IoT infrastructures. It enables secure node registration, access control, and consensus participation using capability-based tokens and smart contracts. The architecture ensures privacy, authentication, and authorization across distributed and resource-constrained IoT environments by enforcing localized, autonomous trust through a multi-layered model.

---

## Key Features

-   **Decentralized Trust**: Uses a private permissioned blockchain (Hyperledger Besu) to manage identity, capability tokens, and validator consensus.
-   **Layered Architecture**:
  - **Device Layer**: Hosts IoT nodes (sensors, edge, fog, cloud)
  - **Blockchain Layer**: Governs identity and policy enforcement
  - **Trust Enforcement Layer**: Verifies identity, access control, and validator eligibility
  - **Communication Layer**: Exposes secure REST APIs
  - **Application Layer**: Bootstraps and orchestrates system services

---

## Functional Phases

1. **Initialization**: The root node creates the genesis block, initializes the blockchain, and deploys smart contracts.
2. **Node Registration**: New nodes register via signed payloads; metadata is verified and stored on-chain.
3. **Validator Proposal**: If eligible, a node is proposed as validator through a consensus mechanism.
4. **Resource Access**: Registered nodes interact via `/read`, `/write`, `/update`, `/remove`, governed by token policies.

---

## Technologies Used

| Layer             | Technology                                |
|------------------|--------------------------------------------|
| Blockchain Layer | Hyperledger Besu, Solidity, Truffle        |
| API Layer        | Flask (Python)                             |
| Web3 Interface   | JavaScript (Web3.js)                       |
| Orchestration    | Shell Scripts                              |

---

## How to Use

Typical command structure to start or interact with the system:

```bash
# Initialize root node
./start_root_services.sh init-chain-root
./start_root_services.sh start-chain-root
./start_root_services.sh admin

# Register new node
./start_root_services.sh register <node_id> <node_name> <node_type> <port>

# Access resource
./start_root_services.sh read-data <node_id> <node_name> <node_type> <port>
./start_root_services.sh write-data ...