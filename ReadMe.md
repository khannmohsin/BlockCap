# DTEA: Distributed Trust Enforcement Architecture for Distributed IoT Infrastructure

## Overview

**DTEA** (Distributed Trust Enforcement Architecture) is a blockchain-enabled security framework designed for heterogeneous, decentralized IoT environments. It provides fine-grained access control, node registration, and role-aware consensus participation via smart contracts and capability-based tokens. The layered architecture supports localized trust enforcement, secure communication, and dynamic scalability across constrained and high-performance nodes.

---
![Alt Text](DTEA_ARchitecture.png)


## Key Features

- **Decentralized Trust Management**: Utilizes Hyperledger Besu (PoA-QBFT) for managing identities and enforcing smart contract logic across validator nodes.
- **Layered Security Design**:
  - **Device Layer**: Physical and virtual nodes including sensors, actuators, edge, fog, and cloud.
  - **Blockchain Layer**: Manages identity registration, access policies, and consensus state.
  - **Trust Enforcement Layer**: Governs dynamic node registration, token issuance, and validator coordination.
  - **Communication Layer**: Exposes REST APIs for secure resource interaction.
  - **Application Layer**: Handles orchestration logic and gateway control.
- **Capability Tokens**: Bidirectional, role-based access control with scoped permissions and expiry.
- **Role-Aware Deployment**: Distributes responsibilities based on node roles—Cloud/Fog (validators), Edge (non-validator), Endpoint (lightweight).

---

## Functional Phases

1. **Initialization**: Cloud node initializes blockchain, configures consensus, and deploys contracts.
2. **Node Registration**: Nodes send signed payloads for registration; verified and stored on-chain.
3. **Validator Proposal**: Validators are dynamically proposed and approved using smart contracts.
4. **Access Control**: `/read`, `/write`, `/update`, and `/remove` are authorized using capability tokens.

---

## Technology Stack

| Layer               | Tools / Technologies                            |
|--------------------|-------------------------------------------------|
| Blockchain Layer   | Hyperledger Besu, Solidity                      |
| Trust Enforcement  | Python (Flask, Web3.py), Shell scripts          |
| Communication      | RESTful APIs (Flask), Prometheus, Grafana       |
| Orchestration      | Shell-based CLI tools                           |
| Monitoring         | Prometheus Node Exporter, Python instrumentation|

---

## Metrics and Monitoring

- **Grafana UI**: [http://localhost:3000](http://localhost:3000)
- **Prometheus UI**: [http://localhost:9090](http://localhost:9090)

Launch Grafana:
```bash
cd /path/to/grafana
./bin/grafana-server web
```

Launch Prometheus:
```bash
prometheus --config.file=prometheus.yml
```

Launch Node Exporter:
```bash
cd /path/to/node_exporter
./node_exporter
```

---

## Sample Node Commands

### Cloud Node
```bash
./start_root_services.sh reinit-chain-root
./start_root_services.sh start-chain-root
./start_root_services.sh admin
./start_root_services.sh self-register CL-001 Cloudy Cloud
./start_root_services.sh read-data CL-001 Cloudy Cloud 127.0.0.1:5001
./start_root_services.sh write-data CL-001 Cloudy Cloud 127.0.0.1:5001
./start_root_services.sh remove-data CL-001 Cloudy Cloud 127.0.0.1:5001
./start_root_services.sh update-data CL-001 Cloudy Cloud 127.0.0.1:5001
```

### Fog Node
```bash
./start_client_services.sh reinit-chain-client
./start_client_services.sh register FG-001 Foggy001 Fog 127.0.0.1:5000
./start_client_services.sh read-data FG-001 Foggy001 Fog 127.0.0.1:5000
./start_client_services.sh remove-data FG-001 Foggy001 Fog 127.0.0.1:5000
./start_client_services.sh update-data FG-001 Foggy001 Fog 127.0.0.1:5000
```

---

## Device Setup 

### Prerequisites
- Ubuntu 20.04 LTS
- OpenJDK 21, Python 3.13+, Node.js 20.x

### Java
```bash
sudo apt install openjdk-21-jdk
```

### Besu Installation
```bash
curl -L https://hyperledger.jfrog.io/artifactory/besu-binaries/besu/25.1.0/besu-25.1.0.zip -o besu.zip
unzip besu.zip
sudo mv besu-25.1.0 /opt/besu
sudo ln -s /opt/besu/bin/besu /usr/local/bin/besu
```

### Python Setup (Pyenv for Pi)
```bash
curl https://pyenv.run | bash
pyenv install 3.13.2
pyenv global 3.13.2
```

### Node.js Setup (NVM)
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
nvm install 20.18.3
nvm use 20.18.3
npm install web3 dotenv
```

---

## Running the System Locally
```bash
git clone https://github.com/khannmohsin/DTEA.git
cd DTEA
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Access Control APIs

All registered nodes expose RESTful APIs:
```http
POST /register-node
POST /read
POST /write
POST /update
POST /remove
```
Authorization is governed by on-chain capability tokens issued to valid nodes.

---

## Performance Metrics Captured
- **Execution Duration**: Per function using decorators
- **Memory Usage**: Heap memory (tracemalloc)
- **CPU Time**: User + System time (resource.getrusage)
- **Prometheus Export**: Metrics available on `/metrics` endpoint

---

## Remote Result Collection

To collect `measurements/` from distributed nodes:
```bash
scp -r <user>@<ip>:/home/<user>/DTEA/Node_client/measurements /local/path
```

---

## License
MIT License. See [LICENSE](./LICENSE).

---

## Acknowledgment
This project is developed and evaluated as part of research on distributed trust and capability-based security in IoT infrastructures. Full paper, documentation, and results are available in the repository.




./start_root_services.sh root-node-register ROOT1 "Root Node" Cloud true 

./start_client_services.sh register FOG001 "Weather Station" Fog 127.0.0.1:5000
./start_root_services.sh policy-next-id

./start_root_services.sh policy-create Cloud Edge "GET,POST" "device:v1:temperature"
./start_root_services.sh policy-create Fog   Edge "READ,UPDATE" "device:v1:firmware"

./start_root_services.sh policy-update 1 "READ,WRITE" "device:v1:temperature"

./start_root_services.sh policy-deprecate 1

curl -X POST http://127.0.0.1:5000/access \
  -H "Content-Type: application/json" \
  -d '{
    "from_signature": "0x552ff729647c57419731b64caa5642fdfcabe49ff75e7bf635ca3db52ca879a46a623825d4647f16314f74af91dfbc6227a7a5d829973cca8572d4f38185c50000",
    "to_signature": "0x7fa336d24e25ea36c3ac7de5235676aa9a755a9cb9b3e49d186f0d9f1bc3d8fb596d45bccbe426ec123c6498876d9c23fce4ae1d13e286721e7f19527619c49801",
    "method": "GET",
    "resource_path": "/temperature",
    "expiry_secs": 900,
    "allow_delegation": false,
    "delegation_depth": 0
  }'

  curl -X POST http://127.0.0.1:5000/access \
  -H "Content-Type: application/json" \
  -d '{
    "from_signature": "0x552ff729647c57419731b64caa5642fdfcabe49ff75e7bf635ca3db52ca879a46a623825d4647f16314f74af91dfbc6227a7a5d829973cca8572d4f38185c50000",
    "to_signature": "0x7fa336d24e25ea36c3ac7de5235676aa9a755a9cb9b3e49d186f0d9f1bc3d8fb596d45bccbe426ec123c6498876d9c23fce4ae1d13e286721e7f19527619c49801",
    "method": "GET",
    "resource_path": "/firmware",
    "expiry_secs": 900
  }'

  curl -s "http://127.0.0.1:5000/alerts?from_signature=0x84235f88bdb9aceae4b3caec17b0500523c90b0c332e67908b60664c1159e41e03077367b9cf72126fba8f225ae54decebf4ed57e516e416b67083b987b1eb1b01&to_signature=0xb289a8543904153a9d1e3856c71934893b22bb9bb97af9dc2091ce3775469b5a39fb2de0a94c154f6caa0266f5c02aa8c4cc515119ae41967ddebf71cc48c2e101&resource_path=/alerts"

  
./start_root_services.sh policy-create Fog Cloud GET "api:GET:/alerts"

node interact.js issueGrant \  
  0x580d38c7c7b8c4e37935c25261fef225a0356c91dee7a00535a465dd08abb5d73d6425257c99ef2224405cbc23eaaec3ecf1a6c4383446265f6a36d3ff6faf6800 \
  0x6f169349d702f9c1a21507127bd764b65f2e38d9ac9cf95be533c060ca03bccd2db03fedcbf93587d0d50f6745760eba58eb563def9387908f21f2b44537f17201 \
  2 READ +900