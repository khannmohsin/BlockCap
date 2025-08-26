// interact.js
// Run: node interact.js help

const { Web3 } = require("web3");
const path = require("path");
const fs = require("fs");
const fetch = require("node-fetch");

// ---------- FIXED SETTINGS ----------
const rootPath = path.resolve(__dirname, "");
const contractJson = require(path.join(rootPath, "data/NodeRegistry.json")); // Load ABI
const rpcURL = "http://127.0.0.1:8545";
const web3 = new Web3(rpcURL);

// Resolve deployed address from Truffle-style artifact
const networks = contractJson.networks || {};
const networkId = Object.keys(networks)[0];
if (!networkId) {
  console.error("No networks{} found in data/NodeRegistry.json");
  process.exit(1);
}
const contractAddress = networks[networkId].address;
if (!contractAddress) {
  console.error("No contract address in data/NodeRegistry.json networks[]");
  process.exit(1);
}

// Load prefunded keys (fixed source)
const accountsData = JSON.parse(fs.readFileSync(path.join(rootPath, "prefunded_keys.json")));
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

// Contract instance
const contract = new web3.eth.Contract(contractJson.abi, contractAddress);

// ---------- ENUMS / CONSTANTS ----------
const ROLE = { Unknown:0, Cloud:1, Fog:2, Edge:3, Sensor:4, Actuator:5 };
const OP   = { READ:1<<0, WRITE:1<<1, UPDATE:1<<2, REMOVE:1<<3 };
const ZERO32 = "0x" + "00".repeat(32);

// ---------- TX HELPER ----------
async function sendTx(method, gas = 3_000_000, value = "0") {
  const data = method.encodeABI();
  const nonce = await web3.eth.getTransactionCount(account, "pending");
  const tx = {
    from: account,
    to: contractAddress,
    data,
    gas,
    gasPrice: "0",
    nonce,
    value
  };
  const signed = await web3.eth.accounts.signTransaction(tx, privateKey);
  return web3.eth.sendSignedTransaction(signed.rawTransaction);
}

function jsonReplacer(key, value) {
  return typeof value === 'bigint' ? value.toString() : value;
}

// ---------- SMALL UTILS ----------
function parseOps(csvOrMask) {
  if (csvOrMask === undefined) throw new Error("opsCsvOrMask is required");
  if (/^\d+$/.test(csvOrMask)) return parseInt(csvOrMask, 10);
  const toOne = (s) => s.replace(/\s/g, "").toUpperCase();
  const parts = csvOrMask.split(/[|,]/).map(s => toOne(s)).filter(Boolean);
  let mask = 0;
  for (const p of parts) {
    if (!(p in OP)) throw new Error(`Unknown op: ${p}`);
    mask |= OP[p];
  }
  return mask;
}
function toBytes32(hexOrStr) {
  if (!hexOrStr) return ZERO32;
  if (hexOrStr.startsWith("0x")) {
    const clean = hexOrStr.slice(2);
    if (clean.length > 64) throw new Error("bytes32 too long");
    return "0x" + clean.padStart(64, "0");
  }
  return web3.utils.keccak256(hexOrStr);
}
function tsNowPlus(seconds) {
  const now = Math.floor(Date.now()/1000);
  return now + Number(seconds || 0);
}

// =========================================================
//                       ADMIN / POLICY
// =========================================================
async function setPolicyAdmin(newAdmin) {
  const rc = await sendTx(contract.methods.setPolicyAdmin(newAdmin));
  console.log("✅ setPolicyAdmin:", rc.transactionHash);
}

async function createPolicy(fromRoleName, toRoleName, opsCsvOrMask, ctxSchemaStrOrHex) {
  const fromRole = ROLE[fromRoleName] ?? Number(fromRoleName);
  const toRole   = ROLE[toRoleName]   ?? Number(toRoleName);
  const ops      = parseOps(opsCsvOrMask);
  const schema   = toBytes32(ctxSchemaStrOrHex || ZERO32);
  const rc = await sendTx(contract.methods.createPolicy(fromRole, toRole, ops, schema));
  console.log("✅ createPolicy:", rc.transactionHash);
}

async function updatePolicy(policyId, opsCsvOrMask, ctxSchemaStrOrHex) {
  const ops    = parseOps(opsCsvOrMask);
  const schema = toBytes32(ctxSchemaStrOrHex || ZERO32);
  const rc = await sendTx(contract.methods.updatePolicy(Number(policyId), ops, schema));
  console.log("✅ updatePolicy:", rc.transactionHash);
}

async function deprecatePolicy(policyId) {
  const rc = await sendTx(contract.methods.deprecatePolicy(Number(policyId)));
  console.log("✅ deprecatePolicy:", rc.transactionHash);
}

async function getPolicy(policyId) {
  const p = await contract.methods.getPolicy(Number(policyId)).call();
  console.log(JSON.stringify(p, jsonReplacer, 2));
}

// =========================================================
//                       MULTISIG (NEW)
// =========================================================
async function msigMode(requiredBool) {
  const req = (String(requiredBool).toLowerCase() === "true" || requiredBool === "1");
  const rc = await sendTx(contract.methods.setMsigMode(req));
  console.log("✅ setMsigMode:", req, rc.transactionHash);
}

async function msigAdd(approverAddr) {
  const rc = await sendTx(contract.methods.addMsigApprover(approverAddr));
  console.log("✅ addMsigApprover:", approverAddr, rc.transactionHash);
}

async function msigRemove(approverAddr) {
  const rc = await sendTx(contract.methods.removeMsigApprover(approverAddr));
  console.log("✅ removeMsigApprover:", approverAddr, rc.transactionHash);
}

async function msigThreshold(k) {
  const rc = await sendTx(contract.methods.setMsigThreshold(Number(k)));
  console.log("✅ setMsigThreshold:", k, rc.transactionHash);
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

async function approveCreatePolicy(fromRoleName, toRoleName, opsCsvOrMask, ctxSchemaStrOrHex) {
  const fromRole = ROLE[fromRoleName] ?? Number(fromRoleName);
  const toRole   = ROLE[toRoleName]   ?? Number(toRoleName);
  const ops      = parseOps(opsCsvOrMask);
  const schema   = toBytes32(ctxSchemaStrOrHex || ZERO32);
  const rc = await sendTx(contract.methods.approveCreatePolicy(fromRole, toRole, ops, schema));
  console.log("✅ approveCreatePolicy:", rc.transactionHash);
}

// =========================================================
/*                    NODES (PACKED)                       */
// =========================================================
/**
 * Calls registerNodePacked(bytes) by ABI-encoding:
 * (string nodeId, string nodeName, string nodeTypeStr, string publicKey,
 *  address registeredByAddr, string rpcURL, string registeredByNodeTypeStr, string nodeSignature)
 */
async function registerNode(nodeId, nodeName, nodeTypeStr, publicKey, registeredByAddr, rpcURL, registeredByNodeTypeStr, nodeSignature) {
  const payload = web3.eth.abi.encodeParameters(
    ["string","string","string","string","address","string","string","string"],
    [ nodeId,  nodeName,  nodeTypeStr,  publicKey,  registeredByAddr,  rpcURL,  registeredByNodeTypeStr,  nodeSignature ]
  );
  const rc = await sendTx(contract.methods.registerNodePacked(payload));
  console.log("✅ registerNodePacked:", rc.transactionHash);
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

async function proposeValidator(validatorAddr) {
  const rc = await sendTx(contract.methods.proposeValidator(validatorAddr));
  console.log("✅ proposeValidator:", rc.transactionHash);
}

async function isValidator(nodeSignature) {
  try {
    const ok = await contract.methods.isValidator(nodeSignature).call();
    console.log(ok);
  } catch {
    console.log(false);
  }
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

async function issueGrantDelegable(fromNodeSig, toNodeSig, policyId, opsCsvOrMask, expiresAtTs, delegationAllowed, delegationDepth) {
  const ops = parseOps(opsCsvOrMask);
  const exp = /^\d+$/.test(expiresAtTs) ? Number(expiresAtTs) : tsNowPlus(Number(expiresAtTs || 0));
  const allow = (String(delegationAllowed).toLowerCase() === "true" || delegationAllowed === "1");
  const depth = Number(delegationDepth || 0);
  const rc = await sendTx(
    contract.methods.issueGrantDelegable(fromNodeSig, toNodeSig, Number(policyId), ops, exp, allow, depth)
  );
  console.log("✅ issueGrantDelegable:", rc.transactionHash);
}

async function revokeGrant(fromNodeSig, toNodeSig) {
  const rc = await sendTx(contract.methods.revokeGrant(fromNodeSig, toNodeSig));
  console.log("✅ revokeGrant:", rc.transactionHash);
}

async function getGrant(fromNodeSig, toNodeSig) {
  const g = await contract.methods.getGrant(fromNodeSig, toNodeSig).call();
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

// NEW: extended view including delegation flags
async function getGrantEx(fromNodeSig, toNodeSig) {
  const g = await contract.methods.getGrantEx(fromNodeSig, toNodeSig).call();
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

async function checkGrant(fromNodeSig, toNodeSig, opCsvOrMask) {
  const opBit = parseOps(opCsvOrMask);
  const ok = await contract.methods.checkGrant(fromNodeSig, toNodeSig, opBit).call();
  console.log(ok);
}

async function isGrantExpired(fromNodeSig, toNodeSig) {
  const ok = await contract.methods.isGrantExpired(fromNodeSig, toNodeSig).call();
  console.log(ok);
}

// NEW: delegate an existing grant (owner of current grantee calls this)
async function delegateGrant(currentFromSig, toSig, newFromSig, opsCsvOrMask, expiresAtTs) {
  const ops = parseOps(opsCsvOrMask);
  const exp = /^\d+$/.test(expiresAtTs) ? Number(expiresAtTs) : tsNowPlus(Number(expiresAtTs || 0));
  const rc = await sendTx(
    contract.methods.delegateGrant(currentFromSig, toSig, newFromSig, ops, exp)
  );
  console.log("✅ delegateGrant:", rc.transactionHash);
}

// =========================================================
//                     BESU UTILS / EVENTS
// =========================================================
async function qbft_getValidatorsByBlockNumber(url = rpcURL) {
  const payload = { jsonrpc:"2.0", method:"qbft_getValidatorsByBlockNumber", params:["latest"], id:1 };
  const res = await fetch(url, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(payload) });
  const data = await res.json();
  console.log(data.result || data);
}

async function net_peerCount(url = rpcURL) {
  const payload = { jsonrpc:"2.0", method:"net_peerCount", params:[], id:1 };
  const res = await fetch(url, { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(payload) });
  const data = await res.json();
  const n = data.result ? parseInt(data.result, 16) : 0;
  console.log(n);
}

async function checkIfDeployed(addr = contractAddress) {
  const code = await web3.eth.getCode(addr);
  console.log(code !== "0x" && code !== "0x0");
}

// =========================================================
//                           CLI
// =========================================================
async function main() {
  const [cmd, ...args] = process.argv.slice(2);

  try {
    switch (cmd) {
      case "help":
        console.log(`
RPC: ${rpcURL}
Contract: ${contractAddress}
From (PREFUNDED[FROM_IDX]): ${account}  (FROM_IDX=${DEFAULT_FROM_IDX})

Set signer per command via env var:
  FROM_IDX=2 node interact.js <command> ...

Roles: Cloud,Fog,Edge,Sensor,Actuator
Ops: READ,WRITE,UPDATE,REMOVE (or numeric mask, or "READ|REMOVE")

Admin/Policy:
  node interact.js setPolicyAdmin <newAdmin>
  node interact.js createPolicy <fromRole> <toRole> <opsCsv|mask> [ctxSchemaStrOrHex]
  node interact.js updatePolicy <policyId> <opsCsv|mask> [ctxSchemaStrOrHex]
  node interact.js deprecatePolicy <policyId>
  node interact.js getPolicy <policyId>

Multisig:
  node interact.js msigMode <true|false>
  node interact.js msigAdd <approverAddr>
  node interact.js msigRemove <approverAddr>
  node interact.js msigThreshold <k>
  node interact.js msigInfo
  node interact.js msigIsApprover <addr>
  node interact.js approveCreatePolicy <fromRole> <toRole> <opsCsv|mask> [ctxSchemaStrOrHex]

Nodes (packed register):
  node interact.js registerNode <nodeId> <nodeName> <nodeTypeStr> <publicKey> <registeredByAddr> <rpcURL> <registeredByNodeTypeStr> <nodeSignature>
  node interact.js isNodeRegistered <nodeSignature>
  node interact.js getNodeBySig <nodeSignature>
  node interact.js getNodeByAddr <address>
  node interact.js proposeValidator <validatorAddr>
  node interact.js isValidator <nodeSignature>

Grants:
  node interact.js issueGrant <fromSig> <toSig> <policyId> <opsCsv|mask> <expiresAtTs or +seconds>
  node interact.js issueGrantDelegable <fromSig> <toSig> <policyId> <opsCsv|mask> <expiresAtTs or +seconds> <delegationAllowed:true|false> <delegationDepth>
  node interact.js delegateGrant <currentFromSig> <toSig> <newFromSig> <opsCsv|mask> <expiresAtTs or +seconds>
  node interact.js revokeGrant <fromSig> <toSig>
  node interact.js getGrant <fromSig> <toSig>
  node interact.js getGrantEx <fromSig> <toSig>
  node interact.js checkGrant <fromSig> <toSig> <opCsv|mask>
  node interact.js isGrantExpired <fromSig> <toSig>

Besu/Utils:
  node interact.js qbft_getValidators
  node interact.js peerCount
  node interact.js checkIfDeployed
`); break;

      // Admin/Policy
      case "setPolicyAdmin": await setPolicyAdmin(args[0]); break;
      case "createPolicy":   await createPolicy(args[0], args[1], args[2], args[3]); break;
      case "updatePolicy":   await updatePolicy(args[0], args[1], args[2]); break;
      case "deprecatePolicy":await deprecatePolicy(args[0]); break;
      case "getPolicy":      await getPolicy(args[0]); break;

      // Multisig
      case "msigMode":       await msigMode(args[0]); break;
      case "msigAdd":        await msigAdd(args[0]); break;
      case "msigRemove":     await msigRemove(args[0]); break;
      case "msigThreshold":  await msigThreshold(args[0]); break;
      case "msigInfo":       await msigInfo(); break;
      case "msigIsApprover": await msigIsApprover(args[0]); break;
      case "approveCreatePolicy": await approveCreatePolicy(args[0], args[1], args[2], args[3]); break;

      // Nodes (packed)
      case "registerNode":     await registerNode(...args); break;
      case "isNodeRegistered": await isNodeRegistered(args[0]); break;
      case "getNodeBySig":     await getNodeDetailsBySignature(args[0]); break;
      case "getNodeByAddr":    await getNodeDetailsByAddress(args[0]); break;
      case "proposeValidator": await proposeValidator(args[0]); break;
      case "isValidator":      await isValidator(args[0]); break;

      // Grants
      case "issueGrant":     await issueGrant(args[0], args[1], args[2], args[3], args[4]); break;
      case "revokeGrant":    await revokeGrant(args[0], args[1]); break;
      case "getGrant":       await getGrant(args[0], args[1]); break;
      case "checkGrant":     await checkGrant(args[0], args[1], args[2]); break;
      case "isGrantExpired": await isGrantExpired(args[0], args[1]); break;
      case "issueGrantDelegable": await issueGrantDelegable(args[0], args[1], args[2], args[3], args[4], args[5], args[6]); break;
      case "delegateGrant":       await delegateGrant(args[0], args[1], args[2], args[3], args[4]); break;
      case "getGrantEx":          await getGrantEx(args[0], args[1]); break;

      // Besu/Utils
      case "qbft_getValidators": await qbft_getValidatorsByBlockNumber(); break;
      case "peerCount":          await net_peerCount(); break;
      case "checkIfDeployed":    await checkIfDeployed(); break;

      default:
        console.log("Unknown command. Run: node interact.js help");
        break;
    }
  } catch (e) {
    console.error("❌ Error:", e?.reason || e?.message || e);
  }
}

if (require.main === module) main();

module.exports = {
  ROLE, OP,
  // Admin/Policy
  setPolicyAdmin, createPolicy, updatePolicy, deprecatePolicy, getPolicy,
  // Multisig
  msigMode, msigAdd, msigRemove, msigThreshold, msigInfo, msigIsApprover, approveCreatePolicy,
  // Nodes
  registerNode, isNodeRegistered, getNodeDetailsBySignature, getNodeDetailsByAddress,
  proposeValidator, isValidator,
  // Grants
  issueGrant, issueGrantDelegable, delegateGrant, revokeGrant, getGrant, getGrantEx, checkGrant, isGrantExpired,
  // Utils
  qbft_getValidatorsByBlockNumber, net_peerCount, checkIfDeployed,
};