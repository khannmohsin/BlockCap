// interact.js (CLIENT version)
// Run: node interact.js help
//
// Client routing rule for TXs:
// - If the provided "routeSig" (a nodeSignature) is NOT a validator, we will:
//    1) Fetch current validator set via qbft_getValidatorsByBlockNumber
//    2) Look up an RPC URL for a validator via RpcUrlMapped events
//    3) Re-route the TX to that validator's RPC
// - Otherwise (validator or no routeSig), use local BESU_RPC_URL.
//
// Notes:
// - Requires .env with BESU_RPC_URL
// - Uses prefunded_keys.json under ./ (same as root) for test keys

const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');
const { Web3 } = require('web3');

// ---------- ENV / PATHS ----------
const rootPath = path.resolve(__dirname, '');

// Load .env BESU_RPC_URL (client nodes use their own RPC)
const dotenvPath = path.resolve(__dirname, '.env');
if (fs.existsSync(dotenvPath)) {
  require('dotenv').config({ path: dotenvPath });
} else {
  console.error('.env file not found! Expected BESU_RPC_URL. Exiting.');
  process.exit(1);
}
const rpcURL_GLOBAL = process.env.BESU_RPC_URL || 'http://127.0.0.1:8546';
const web3 = new Web3(rpcURL_GLOBAL);

// Contract artifact/address
const contractJson = require(path.join(rootPath, 'data/NodeRegistry.json'));
const networks = contractJson.networks || {};
const networkId = Object.keys(networks)[0];
if (!networkId) {
  console.error('No networks{} found in data/NodeRegistry.json');
  process.exit(1);
}
const contractAddress = networks[networkId].address;
if (!contractAddress) {
  console.error('No contract address in data/NodeRegistry.json networks[]');
  process.exit(1);
}

// Keys
const accountsData = JSON.parse(fs.readFileSync(path.join(rootPath, 'prefunded_keys.json')));
const PREFUNDED = accountsData.prefunded_accounts || [];
const DEFAULT_FROM_IDX = Number(process.env.FROM_IDX || 0);
if (!PREFUNDED[DEFAULT_FROM_IDX]) {
  console.error(`No prefunded account at index FROM_IDX=${DEFAULT_FROM_IDX}`);
  process.exit(1);
}
function walletAt(idx) {
  const w = PREFUNDED[idx];
  if (!w) throw new Error(`No prefunded account at index ${idx}`);
  return { address: w.address, privateKey: w.private_key };
}
let { address: account, privateKey } = walletAt(DEFAULT_FROM_IDX);

// Base contract (for read-only + events on local RPC)
const contract = new web3.eth.Contract(contractJson.abi, contractAddress);

// ---------- ENUMS / CONSTANTS ----------
const ROLE = { Unknown:0, Cloud:1, Fog:2, Edge:3, Sensor:4, Actuator:5 };
const OP   = { READ:1<<0, WRITE:1<<1, UPDATE:1<<2, REMOVE:1<<3 };
const ZERO32 = '0x' + '00'.repeat(32);

// ---------- ROUTING HELPERS ----------

// --- add near the other event/utils helpers ---
async function msigApprovedEvents(fromBlock = 0) {
  const evs = await contract.getPastEvents('MsigApproved', {
    fromBlock: Number(fromBlock),
    toBlock: 'latest'
  });

  console.log(JSON.stringify(
    evs.map(e => ({
      blockNumber: e.blockNumber,
      tx: e.transactionHash,
      approver: e.returnValues.approver,
      approvals: Number(e.returnValues.approvals),
      actionKey: e.returnValues.actionKey
    })), 
    jsonReplacer,  // <-- use replacer here
    2
  ));
}

async function msigClearedEvents(fromBlock = 0) {
  const evs = await contract.getPastEvents('MsigCleared', { fromBlock: Number(fromBlock), toBlock: 'latest' });
  console.log(JSON.stringify(evs.map(e => ({
    blockNumber: e.blockNumber,
    tx: e.transactionHash,
    actionKey: e.returnValues.actionKey
  })), null, 2));
}

/** Fetch current QBFT validator set (addresses) using the provided RPC URL. */
async function getValidatorsByBlockNumber(rpcUrl = rpcURL_GLOBAL) {
  const payload = { jsonrpc: '2.0', method: 'qbft_getValidatorsByBlockNumber', params: ['latest'], id: 1 };
  try {
    const res = await fetch(rpcUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await res.json();
    if (data && data.result) {
      // console.log(data.result);
      return data.result;
    }
  } catch (e) {
    console.error('Failed to get validators:', e);
  }
  return [];
}

/** Build mapping { validatorAddrLower => rpcURLLower } from RpcUrlMapped events. */
async function watchRpcUrlMappings() {
  try {
    const pastEvents = await contract.getPastEvents('RpcUrlMapped', { fromBlock: 0, toBlock: 'latest' });
    const rpcMapping = {};
    for (const ev of pastEvents) {
      const addr = String(ev.returnValues.nodeAddress || '').toLowerCase();
      const url  = String(ev.returnValues.rpcURL || '');
      if (addr && url) rpcMapping[addr] = url.toLowerCase();
    }
    return rpcMapping;
  } catch (err) {
    console.error('Error reading RpcUrlMapped events:', err);
    return {};
  }
}

/** Lightweight read that asks the contract if a nodeSignature is a validator. */
async function isValidator(nodeSignature) {
  try {
    const ok = await contract.methods.isValidator(nodeSignature).call();
    // console.log(ok);
    return !!ok;
  } catch {
    // console.log(false);
    return false;
  }
}

async function whoami() {
  const idx = Number(process.env.FROM_IDX || 0);
  const { address: from } = walletAt(idx);  // from prefunded_keys.json
  const bal = await web3.eth.getBalance(from);
  console.log(JSON.stringify({
    fromIndex: idx,
    from,
    balanceWei: bal.toString()   // convert BigInt → string
  }, null, 2));
}

/**
 * Decide which Web3 instance to use for a transaction.
 * If routeSig is provided and NOT a validator => route through first validator that has an RPC mapping.
 * Otherwise use the local web3 (rpcURL_GLOBAL).
 */
async function pickWeb3(routeSig) {
  // Default to local
  let chosen = web3;

  if (!routeSig) return chosen;

  const sigIsValidator = await isValidator(routeSig);
  if (sigIsValidator) return chosen;

  // Not a validator -> find a validator + its RPC URL via mapping
  const rpcMapping = Object.fromEntries(
    Object.entries(await watchRpcUrlMappings()).map(([k,v]) => [k.toLowerCase(), v.toLowerCase()])
  );
  const validators = await getValidatorsByBlockNumber(rpcURL_GLOBAL); // array of addresses
  if (validators.length) {
    const candidate = String(validators[0] || '').toLowerCase();
    if (candidate && rpcMapping[candidate]) {
      // Route through validator RPC
      try {
        chosen = new Web3(rpcMapping[candidate]);
        // console.log(`Routing TX via validator ${candidate} @ ${rpcMapping[candidate]}`);
      } catch (e) {
        console.error('Failed to create Web3 for mapped validator RPC, falling back:', e.message);
      }
    } else {
      console.log(`Validator ${candidate} not found in RpcUrlMapped mapping; using local RPC.`);
    }
  }
  return chosen;
}

/** Factory: get a Contract object bound to a given web3 */
function contractFor(w3) {
  return new w3.eth.Contract(contractJson.abi, contractAddress);
}

// ---------- TX HELPER ----------
async function sendTx(method, gas = 3_000_000, value = '0', w3 = web3) {
  const data = method.encodeABI();
  const nonce = await w3.eth.getTransactionCount(account, 'pending');
  const tx = { from: account, to: contractAddress, data, gas, gasPrice: '0', nonce, value };
  const signed = await w3.eth.accounts.signTransaction(tx, privateKey);
  return w3.eth.sendSignedTransaction(signed.rawTransaction);
}

function jsonReplacer(key, value) {
  return typeof value === 'bigint' ? value.toString() : value;
}

// ---------- SMALL UTILS ----------
function parseOps(csvOrMask) {
  if (csvOrMask === undefined) throw new Error('opsCsvOrMask is required');
  if (/^\d+$/.test(csvOrMask)) return parseInt(csvOrMask, 10);
  const toOne = (s) => s.replace(/\s/g, '').toUpperCase();
  const parts = csvOrMask.split(/[|,]/).map((s) => toOne(s)).filter(Boolean);
  let mask = 0;
  for (const p of parts) {
    if (!(p in OP)) throw new Error(`Unknown op: ${p}`);
    mask |= OP[p];
  }
  return mask;
}

function toBytes32(hexOrStr) {
  if (!hexOrStr) return ZERO32;
  if (hexOrStr.startsWith('0x')) {
    const clean = hexOrStr.slice(2);
    if (clean.length > 64) throw new Error('bytes32 too long');
    return '0x' + clean.padStart(64, '0');
  }
  return web3.utils.keccak256(hexOrStr);
}
function tsNowPlus(seconds) {
  const now = Math.floor(Date.now() / 1000);
  return now + Number(seconds || 0);
}

async function nextPolicyId() {
  const id = await contract.methods.nextPolicyId().call();
  console.log(Number(id));
}

// =========================================================
//                       ADMIN / POLICY
// =========================================================

async function policyAdmin() {
  const admin = await contract.methods.policyAdmin().call();
  console.log(admin);
}

async function setPolicyAdmin(newAdmin, routeSig) {
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.setPolicyAdmin(newAdmin), 300000, '0', w3);
  console.log('✅ setPolicyAdmin:', rc.transactionHash);
}

async function createPolicy(fromRoleName, toRoleName, opsCsvOrMask, ctxSchemaStrOrHex, routeSig) {
  const fromRole = ROLE[fromRoleName] ?? Number(fromRoleName);
  const toRole   = ROLE[toRoleName]   ?? Number(toRoleName);
  const ops      = parseOps(opsCsvOrMask);
  const schema   = toBytes32(ctxSchemaStrOrHex || ZERO32);
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.createPolicy(fromRole, toRole, ops, schema), 3_000_000, '0', w3);
  console.log('✅ createPolicy:', rc.transactionHash);
}

async function updatePolicy(policyId, opsCsvOrMask, ctxSchemaStrOrHex, routeSig) {
  const ops    = parseOps(opsCsvOrMask);
  const schema = toBytes32(ctxSchemaStrOrHex || ZERO32);
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.updatePolicy(Number(policyId), ops, schema), 3_000_000, '0', w3);
  console.log('✅ updatePolicy:', rc.transactionHash);
}

async function deprecatePolicy(policyId, routeSig) {
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.deprecatePolicy(Number(policyId)), 300000, '0', w3);
  console.log('✅ deprecatePolicy:', rc.transactionHash);
}

async function getPolicy(policyId) {
  const p = await contract.methods.getPolicy(Number(policyId)).call();
  console.log(JSON.stringify(p, jsonReplacer, 2));
}

// =========================================================
//                       MULTISIG
// =========================================================
async function msigMode(requiredBool, routeSig) {
  const req = (String(requiredBool).toLowerCase() === 'true' || requiredBool === '1');
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.setMsigMode(req), 300000, '0', w3);
  console.log('✅ setMsigMode:', req, rc.transactionHash);
}

async function msigAdd(approverAddr, routeSig) {
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.addMsigApprover(approverAddr), 300000, '0', w3);
  console.log('✅ addMsigApprover:', approverAddr, rc.transactionHash);
}

async function msigRemove(approverAddr, routeSig) {
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.removeMsigApprover(approverAddr), 300000, '0', w3);
  console.log('✅ removeMsigApprover:', approverAddr, rc.transactionHash);
}

async function msigThreshold(k, routeSig) {
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.setMsigThreshold(Number(k)), 300000, '0', w3);
  console.log('✅ setMsigThreshold:', k, rc.transactionHash);
}

async function msigInfo() {
  const required  = await contract.methods.msigRequired().call();
  const count     = await contract.methods.msigApproverCount().call();
  const threshold = await contract.methods.msigThreshold().call();
  console.log(JSON.stringify({
    msigRequired: required,
    msigApproverCount: Number(count),
    msigThreshold: Number(threshold),
    defaultFrom: { index: DEFAULT_FROM_IDX, account }
  }, null, 2));
}

async function msigIsApprover(addr) {
  const ok = await contract.methods.msigApprover(addr).call();
  console.log(ok);
}

async function approveCreatePolicy(fromRoleName, toRoleName, opsCsvOrMask, ctxSchemaStrOrHex, routeSig) {
  const fromRole = ROLE[fromRoleName] ?? Number(fromRoleName);
  const toRole   = ROLE[toRoleName]   ?? Number(toRoleName);
  const ops      = parseOps(opsCsvOrMask);
  const schema   = toBytes32(ctxSchemaStrOrHex || ZERO32);
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.approveCreatePolicy(fromRole, toRole, ops, schema), 3_000_000, '0', w3);
  console.log('✅ approveCreatePolicy:', rc.transactionHash);
}

// =========================================================
//                       NODES (PACKED)
// =========================================================
/**
 * Calls registerNodePacked(bytes) by ABI-encoding:
 * (string nodeId, string nodeName, string nodeTypeStr, string publicKey,
 *  address registeredByAddr, string rpcURL, string registeredByNodeTypeStr, string nodeSignature)
 *
 * routeSig (optional): nodeSignature used to decide TX routing (see top-of-file rule).
 */
async function registerNode(nodeId, nodeName, nodeTypeStr, publicKey, registeredByAddr, rpcURL, registeredByNodeTypeStr, nodeSignature, routeSig) {
  const payload = web3.eth.abi.encodeParameters(
    ['string','string','string','string','address','string','string','string'],
    [ nodeId,  nodeName,  nodeTypeStr,  publicKey,  registeredByAddr,  rpcURL,  registeredByNodeTypeStr,  nodeSignature ]
  );
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.registerNodePacked(payload), 3_000_000, '0', w3);
  console.log('✅ registerNodePacked:', rc.transactionHash);
}

async function isNodeRegistered(nodeSignature) {
  const ok = await contract.methods.isNodeRegistered(nodeSignature).call();
  console.log(ok);
}

async function getNodeDetailsBySignature(nodeSignature) {
  const r = await contract.methods.getNodeDetailsBySignature(nodeSignature).call();
  const details = {
    nodeId: r[0], nodeName: r[1], nodeType: Number(r[2]),
    publicKey: r[3], isRegistered: r[4], registeredBy: r[5],
    nodeSignature: r[6], registeredByNodeType: Number(r[7]),
  };
  console.log(JSON.stringify(details, null, 2));
}

async function getNodeDetailsByAddress(addr) {
  const r = await contract.methods.getNodeDetailsByAddress(addr).call();
  const details = {
    nodeId: r[0], nodeName: r[1], nodeType: Number(r[2]),
    publicKey: r[3], isRegistered: r[4], registeredBy: r[5],
    nodeSignature: r[6], registeredByNodeType: Number(r[7]),
  };
  console.log(JSON.stringify(details, null, 2));
}

async function proposeValidator(validatorAddr, routeSig) {
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.proposeValidator(validatorAddr), 300000, '0', w3);
  console.log('✅ proposeValidator:', rc.transactionHash);
}

// =========================================================
//                           GRANTS
// =========================================================
async function issueGrant(fromNodeSig, toNodeSig, policyId, opsCsvOrMask, expiresAtTs) {
  const ops = parseOps(opsCsvOrMask);
  const exp = /^\d+$/.test(expiresAtTs) ? Number(expiresAtTs) : tsNowPlus(Number(expiresAtTs || 0));
  const rc = await sendTx(contract.methods.issueGrant(fromNodeSig, toNodeSig, Number(policyId), ops, exp));
  console.log("✅ issueGrant:", rc.transactionHash);
}


async function issueGrantDelegable(fromNodeSig, toNodeSig, policyId, opsCsvOrMask, expiresAtTs, delegationAllowed, delegationDepth, routeSig) {
  const ops = parseOps(opsCsvOrMask);
  const exp = /^\d+$/.test(expiresAtTs) ? Number(expiresAtTs) : tsNowPlus(Number(expiresAtTs || 0));
  const allow = (String(delegationAllowed).toLowerCase() === 'true' || delegationAllowed === '1');
  const depth = Number(delegationDepth || 0);
  const w3 = await pickWeb3(routeSig);
  const c  = contractFor(w3);
  const rc = await sendTx(c.methods.issueGrantDelegable(fromNodeSig, toNodeSig, Number(policyId), ops, exp, allow, depth), 3_000_000, '0', w3);
  console.log('✅ issueGrantDelegable:', rc.transactionHash);
}

async function revokeGrant(fromNodeSig, toNodeSig, policyId) {
  const rc = await sendTx(contract.methods.revokeGrant(fromNodeSig, toNodeSig, Number(policyId)));
  console.log("✅ revokeGrant:", rc.transactionHash);
}

async function getGrant(fromNodeSig, toNodeSig, policyId) {
  const g = await contract.methods.getGrant(fromNodeSig, toNodeSig, Number(policyId)).call();
  const grant = {
    policyId: Number(g[0]),
    opsSubset: Number(g[1]),
    issuedAt: Number(g[2]),
    expiresAt: Number(g[3]),
    isIssued: g[4],
    isRevoked: g[5],
  };
  console.log(JSON.stringify(grant, null, 2));
}

// Extended view including delegation flags
async function getGrantEx(fromNodeSig, toNodeSig, policyId) {
  const g = await contract.methods.getGrantEx(fromNodeSig, toNodeSig, Number(policyId)).call();
  const grant = {
    policyId: Number(g[0]),
    opsSubset: Number(g[1]),
    issuedAt: Number(g[2]),
    expiresAt: Number(g[3]),
    isIssued: g[4],
    isRevoked: g[5],
    delegationAllowed: g[6],
    delegationDepth: Number(g[7]),
  };
  console.log(JSON.stringify(grant, null, 2));
}

async function checkGrant(fromNodeSig, toNodeSig, policyId, opCsvOrMask) {
  const opBit = parseOps(opCsvOrMask);
  const ok = await contract.methods.checkGrant(fromNodeSig, toNodeSig, Number(policyId), opBit).call();
  console.log(ok);
}

async function isGrantExpired(fromNodeSig, toNodeSig, policyId) {
  const ok = await contract.methods.isGrantExpired(fromNodeSig, toNodeSig, Number(policyId)).call();
  console.log(ok);
}

async function delegateGrant(currentFromSig, toSig, newFromSig, policyId, opsCsvOrMask, expiresAtTs) {
  const ops = parseOps(opsCsvOrMask);
  const exp = /^\d+$/.test(expiresAtTs) ? Number(expiresAtTs) : tsNowPlus(Number(expiresAtTs || 0));
  const rc = await sendTx(
    contract.methods.delegateGrant(currentFromSig, toSig, newFromSig, Number(policyId), ops, exp)
  );
  console.log("✅ delegateGrant:", rc.transactionHash);
}

// =========================================================
//                     BESU UTILS / EVENTS
// =========================================================

async function proposeValidatorVote(validatorAddress, add) {
  const payload = {
    jsonrpc: "2.0",
    method: "qbft_proposeValidatorVote",
    params: [validatorAddress, add],  // add = true to add, false to remove
    id: 1
  };
  const res = await fetch(rpcURL, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  console.log("Vote submitted:", await res.json());
}

async function listenForValidatorProposals(fromBlockHint) {
  // v4 returns BigInt → cast to Number before doing math
  const latest = Number(await web3.eth.getBlockNumber());
  const from   = Math.max(0, Number(fromBlockHint ?? (latest - 64)));

  const evs = await contract.getPastEvents('ValidatorProposed', {
    fromBlock: from,
    toBlock: 'latest'
  });

  // event ValidatorProposed(address indexed proposedBy, address indexed validator);
  const addrs = [...new Set(evs.map(e =>
    e.returnValues.validator || e.returnValues["1"]
  ).filter(Boolean))];

  console.log(addrs.join("\n"));
}

async function qbft_getValidatorsByBlockNumber_cli(url = rpcURL_GLOBAL) {
  const vals = await getValidatorsByBlockNumber(url);
  console.log(vals.length ? vals : []);
}

async function net_peerCount(url = rpcURL_GLOBAL) {
  const payload = { jsonrpc: '2.0', method: 'net_peerCount', params: [], id: 1 };
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  const data = await res.json();
  const n = data.result ? parseInt(data.result, 16) : 0;
  console.log(n);
}

async function checkIfDeployed(addr = contractAddress) {
  const code = await web3.eth.getCode(addr);
  console.log(code !== '0x' && code !== '0x0');
}

// =========================================================
//                           CLI
// =========================================================
async function main() {
  const [cmd, ...args] = process.argv.slice(2);

  try {
    switch (cmd) {
      case 'help':
        console.log(`
RPC: ${rpcURL_GLOBAL}
Contract: ${contractAddress}
From (PREFUNDED[FROM_IDX]): ${account}  (FROM_IDX=${DEFAULT_FROM_IDX})

Routing rule: provide a final [routeSig] arg to TX commands if the caller is non-validator.
If routeSig is not a validator, TX is re-routed via a mapped validator RPC.

Roles: Cloud,Fog,Edge,Sensor,Actuator
Ops: READ,WRITE,UPDATE,REMOVE (or numeric mask, or "READ|REMOVE")

Admin/Policy:
  node interact.js setPolicyAdmin <newAdmin> [routeSig]
  node interact.js createPolicy <fromRole> <toRole> <opsCsv|mask> [ctxSchema] [routeSig]
  node interact.js updatePolicy <policyId> <opsCsv|mask> [ctxSchema] [routeSig]
  node interact.js deprecatePolicy <policyId> [routeSig]
  node interact.js getPolicy <policyId>

Multisig:
  node interact.js msigMode <true|false> [routeSig]
  node interact.js msigAdd <approverAddr> [routeSig]
  node interact.js msigRemove <approverAddr> [routeSig]
  node interact.js msigThreshold <k> [routeSig]
  node interact.js msigInfo
  node interact.js msigIsApprover <addr>
  node interact.js approveCreatePolicy <fromRole> <toRole> <opsCsv|mask> [ctxSchema] [routeSig]

Nodes (packed register):
  node interact.js registerNode <nodeId> <nodeName> <nodeTypeStr> <publicKey> <registeredByAddr> <rpcURL> <registeredByNodeTypeStr> <nodeSignature> [routeSig]
  node interact.js isNodeRegistered <nodeSignature>
  node interact.js getNodeBySig <nodeSignature>
  node interact.js getNodeByAddr <address>
  node interact.js proposeValidator <validatorAddr> [routeSig]
  node interact.js isValidator <nodeSignature>

Grants:
  node interact.js issueGrant <fromSig> <toSig> <policyId> <opsCsv|mask> <expiresAtTs|+sec> [routeSig]
  node interact.js issueGrantDelegable <fromSig> <toSig> <policyId> <opsCsv|mask> <expiresAtTs|+sec> <delegationAllowed:true|false> <delegationDepth> [routeSig]
  node interact.js delegateGrant <currentFromSig> <toSig> <newFromSig> <opsCsv|mask> <expiresAtTs|+sec> [routeSig]
  node interact.js revokeGrant <fromSig> <toSig> [routeSig]
  node interact.js getGrant <fromSig> <toSig>
  node interact.js getGrantEx <fromSig> <toSig>
  node interact.js checkGrant <fromSig> <toSig> <opCsv|mask>
  node interact.js isGrantExpired <fromSig> <toSig>

Besu/Utils:
  node interact.js listenForValidatorProposals [fromBlock]
  node interact.js qbft_getValidators
  node interact.js peerCount
  node interact.js checkIfDeployed
`); break;

      case 'nextPolicyId': await nextPolicyId(); break;

      // Admin/Policy
      case 'setPolicyAdmin': await setPolicyAdmin(args[0], args[1]); break;
      case 'policyAdmin':   await policyAdmin(); break;
      case 'createPolicy':   await createPolicy(args[0], args[1], args[2], args[3], args[4]); break;
      case 'updatePolicy':   await updatePolicy(args[0], args[1], args[2], args[3]); break;
      case 'deprecatePolicy':await deprecatePolicy(args[0], args[1]); break;
      case 'getPolicy':      await getPolicy(args[0]); break;

      // Multisig
      case 'msigMode':       await msigMode(args[0], args[1]); break;
      case 'msigAdd':        await msigAdd(args[0], args[1]); break;
      case 'msigRemove':     await msigRemove(args[0], args[1]); break;
      case 'msigThreshold':  await msigThreshold(args[0], args[1]); break;
      case 'msigInfo':       await msigInfo(); break;
      case 'msigIsApprover': await msigIsApprover(args[0]); break;
      case 'approveCreatePolicy': await approveCreatePolicy(args[0], args[1], args[2], args[3], args[4]); break;

      // Nodes (packed)
      case 'registerNode':     await registerNode(...args); break; // supports optional [routeSig] at end
      case 'isNodeRegistered': await isNodeRegistered(args[0]); break;
      case 'getNodeBySig':     await getNodeDetailsBySignature(args[0]); break;
      case 'getNodeByAddr':    await getNodeDetailsByAddress(args[0]); break;
      case 'proposeValidator': await proposeValidator(args[0], args[1]); break;
      case "proposeValidatorVote": await proposeValidatorVote(args[0], args[1]); break;
      case 'isValidator':      console.log(await isValidator(args[0])); break;

      // Grants
      case "issueGrant":     await issueGrant(args[0], args[1], args[2], args[3], args[4]); break;
      case "revokeGrant":    await revokeGrant(args[0], args[1], args[2]); break;                 // from, to, policyId
      case "getGrant":       await getGrant(args[0], args[1], args[2]); break;                   // from, to, policyId
      case "getGrantEx":     await getGrantEx(args[0], args[1], args[2]); break;                 // from, to, policyId
      case "checkGrant":     await checkGrant(args[0], args[1], args[2], args[3]); break;        // from, to, policyId, op
      case "isGrantExpired": await isGrantExpired(args[0], args[1], args[2]); break;             // from, to, policyId
      case "delegateGrant":  await delegateGrant(args[0], args[1], args[2], args[3], args[4], args[5]); break; // currFrom, to, newFrom, policyId, ops, exp

      // Besu/Utils
      case 'listenForValidatorProposals': await listenForValidatorProposals(args[0]); break;
      case 'qbft_getValidators': await qbft_getValidatorsByBlockNumber_cli(); break;
      case 'peerCount':          await net_peerCount(); break;
      case 'checkIfDeployed':    await checkIfDeployed(); break;
      case 'whoami':            await whoami(); break;
      case "msigApprovedEvents": await msigApprovedEvents(args[0]); break;
      case "msigClearedEvents":  await msigClearedEvents(args[0]); break;

      default:
        console.log('Unknown command. Run: node interact.js help');
        break;
    }
  } catch (e) {
    const msg = e?.reason || e?.message || e;
    console.error('❌ Error:', msg);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  ROLE, OP,
  // Admin/Policy
  policyAdmin, setPolicyAdmin, createPolicy, updatePolicy, deprecatePolicy, getPolicy,
  // Multisig
  msigMode, msigAdd, msigRemove, msigThreshold, msigInfo, msigIsApprover, approveCreatePolicy,
  // Nodes
  registerNode, isNodeRegistered, getNodeDetailsBySignature, getNodeDetailsByAddress,
  proposeValidator, isValidator, proposeValidatorVote,
  // Grants
  issueGrant, issueGrantDelegable, delegateGrant, revokeGrant, getGrant, getGrantEx, checkGrant, isGrantExpired,
  // Utils
  qbft_getValidatorsByBlockNumber: qbft_getValidatorsByBlockNumber_cli, net_peerCount, checkIfDeployed, whoami,
};