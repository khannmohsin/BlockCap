// test/NodeRegistry.full.test.js
const { expect } = require("chai");
const { ethers } = require("hardhat");

// NodeType indices from enum { Unknown=0, Cloud=1, Fog=2, Edge=3, Sensor=4, Actuator=5 }
const ROLE = { Unknown: 0, Cloud: 1, Fog: 2, Edge: 3, Sensor: 4, Actuator: 5 };

// Operation bitmask values (mirror contract)
const OP_READ   = 1 << 0; // 1
const OP_WRITE  = 1 << 1; // 2
const OP_UPDATE = 1 << 2; // 4
const OP_REMOVE = 1 << 3; // 8

// Helper: build packed payload for registerNodePacked(bytes)
function buildRegPayload({
  nodeId, nodeName, nodeTypeStr, publicKey,
  registeredBy, rpcURL, registeredByNodeTypeStr, nodeSignature,
}) {
  const abi = new ethers.AbiCoder();
  return abi.encode(
    ["string","string","string","string","address","string","string","string"],
    [ nodeId, nodeName, nodeTypeStr, publicKey, registeredBy, rpcURL, registeredByNodeTypeStr, nodeSignature ]
  );
}

describe("NodeRegistry — full surface (legacy + delegation)", function () {
  let reg;
  let admin, fogOwner, edgeOwner, sensorOwner, other, rando;

  async function nowTs() {
    const b = await ethers.provider.getBlock("latest");
    return b.timestamp;
  }

  beforeEach(async () => {
    [admin, fogOwner, edgeOwner, sensorOwner, other, rando] = await ethers.getSigners();
    const Reg = await ethers.getContractFactory("NodeRegistry", admin);
    reg = await Reg.deploy();
    await reg.waitForDeployment();
  });

  // --------------------------------------------------------------------
  // LEGACY (policies + nodes + non-delegable grants)
  // --------------------------------------------------------------------
  describe("Legacy flow", () => {
    it("P1: admin-only policy ops and admin transfer", async () => {
      // Non-admin cannot create
      await expect(
        reg.connect(fogOwner).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(reg, "NotPolicyAdmin");

      // Admin can create
      await expect(
        reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ethers.ZeroHash)
      ).to.emit(reg, "PolicyCreated");

      // Admin transfers adminship
      await reg.connect(admin).setPolicyAdmin(fogOwner.address);
      expect(await reg.policyAdmin()).to.equal(fogOwner.address);

      // New admin can create
      await expect(
        reg.connect(fogOwner).createPolicy(ROLE.Fog, ROLE.Edge, OP_READ, ethers.ZeroHash)
      ).to.emit(reg, "PolicyCreated");
    });

    it("P2: create/update/deprecate + getters", async () => {
      await expect(
        reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ethers.ZeroHash)
      ).to.emit(reg, "PolicyCreated");

      let p1 = await reg.getPolicy(1);
      expect(p1.opsAllowed).to.equal(OP_READ | OP_REMOVE);
      expect(p1.version).to.equal(1);
      expect(p1.isDeprecated).to.equal(false);

      await expect(
        reg.connect(admin).updatePolicy(1, OP_READ, ethers.ZeroHash)
      ).to.emit(reg, "PolicyChanged");

      p1 = await reg.getPolicy(1);
      expect(p1.opsAllowed).to.equal(OP_READ);
      expect(p1.version).to.equal(2);

      await expect(reg.connect(admin).deprecatePolicy(1))
        .to.emit(reg, "PolicyDeprecatedEvent");

      p1 = await reg.getPolicy(1);
      expect(p1.isDeprecated).to.equal(true);
    });

    it("P3: policy validation failures", async () => {
      await expect(
        reg.connect(admin).createPolicy(ROLE.Unknown, ROLE.Fog, OP_READ, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(reg, "InvalidRoles");

      await expect(
        reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, 0, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(reg, "EmptyOpsAllowed");

      await reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ, ethers.ZeroHash); // id=1
      await reg.connect(admin).deprecatePolicy(1);

      await expect(
        reg.connect(admin).updatePolicy(1, OP_READ | OP_REMOVE, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(reg, "PolicyDeprecated");
    });

    it("N1: register nodes + lookups + validator flags", async () => {
      expect(await reg.isNodeRegistered("sigFog")).to.equal(false);

      const fogPayload = buildRegPayload({
        nodeId: "FG-1", nodeName: "Foggy", nodeTypeStr: "Fog",
        publicKey: "pubFog", registeredBy: fogOwner.address,
        rpcURL: "rpcFog", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigFog",
      });
      await expect(reg.connect(fogOwner).registerNodePacked(fogPayload))
        .to.emit(reg, "NodeRegistered")
        .and.to.emit(reg, "RpcUrlMapped");

      const edgePayload = buildRegPayload({
        nodeId: "ED-1", nodeName: "Edgey", nodeTypeStr: "Edge",
        publicKey: "pubEdge", registeredBy: edgeOwner.address,
        rpcURL: "rpcEdge", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigEdge",
      });
      await reg.connect(edgeOwner).registerNodePacked(edgePayload);

      expect(await reg.isNodeRegistered("sigFog")).to.equal(true);
      expect(await reg.isNodeRegistered("nope")).to.equal(false);

      const fogBySig = await reg.getNodeDetailsBySignature("sigFog");
      expect(fogBySig[0]).to.equal("FG-1");

      const fogByAddr = await reg.getNodeDetailsByAddress(fogOwner.address);
      expect(fogByAddr[0]).to.equal("FG-1");

      await expect(reg.getNodeDetailsBySignature("unknownSig"))
        .to.be.revertedWithCustomError(reg, "NodeNotRegistered");
      await expect(reg.getNodeDetailsByAddress("0x000000000000000000000000000000000000dEaD"))
        .to.be.revertedWithCustomError(reg, "AddressNotRegistered");

      expect(await reg.isValidator("sigFog")).to.equal(true);
      expect(await reg.isValidator("sigEdge")).to.equal(false);
      await expect(reg.proposeValidator(edgeOwner.address)).to.emit(reg, "ValidatorProposed");
    });

    it("N2: registration validation failures", async () => {
      const badZero = buildRegPayload({
        nodeId: "FG-1", nodeName: "Foggy", nodeTypeStr: "Fog",
        publicKey: "pubFog", registeredBy: ethers.ZeroAddress,
        rpcURL: "rpcFog", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigFog",
      });
      await expect(
        reg.connect(fogOwner).registerNodePacked(badZero)
      ).to.be.revertedWithCustomError(reg, "ZeroAddr");

      const badType = buildRegPayload({
        nodeId: "FG-1", nodeName: "Foggy", nodeTypeStr: "INVALID",
        publicKey: "pubFog", registeredBy: fogOwner.address,
        rpcURL: "rpcFog", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigFog",
      });
      await expect(
        reg.connect(fogOwner).registerNodePacked(badType)
      ).to.be.revertedWithCustomError(reg, "InvalidRoles");

      const ok = buildRegPayload({
        nodeId: "FG-1", nodeName: "Foggy", nodeTypeStr: "Fog",
        publicKey: "pubFog", registeredBy: fogOwner.address,
        rpcURL: "rpcFog", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigFog",
      });
      await reg.connect(fogOwner).registerNodePacked(ok);

      const dupSig = buildRegPayload({
        nodeId: "FG-2", nodeName: "Foggy2", nodeTypeStr: "Fog",
        publicKey: "pubFog2", registeredBy: fogOwner.address,
        rpcURL: "rpcFog2", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigFog",
      });
      await expect(
        reg.connect(fogOwner).registerNodePacked(dupSig)
      ).to.be.revertedWithCustomError(reg, "DuplicateSignature");
    });

    it("G1: issue grant (happy path) and checkGrant", async () => {
      const fogPayload = buildRegPayload({
        nodeId: "FG-1", nodeName: "Foggy", nodeTypeStr: "Fog",
        publicKey: "pubFog", registeredBy: fogOwner.address,
        rpcURL: "rpcFog", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigFog",
      });
      const edgePayload = buildRegPayload({
        nodeId: "ED-1", nodeName: "Edgey", nodeTypeStr: "Edge",
        publicKey: "pubEdge", registeredBy: edgeOwner.address,
        rpcURL: "rpcEdge", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigEdge",
      });
      await reg.connect(fogOwner).registerNodePacked(fogPayload);
      await reg.connect(edgeOwner).registerNodePacked(edgePayload);

      await reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ethers.ZeroHash); // id=1

      const t0 = await nowTs();
      await expect(
        reg.connect(fogOwner).issueGrant("sigEdge","sigFog", 1, OP_READ, t0 + 1800)
      ).to.emit(reg, "GrantIssued");

      expect(await reg.checkGrant("sigEdge","sigFog", OP_READ)).to.equal(true);
      expect(await reg.checkGrant("sigEdge","sigFog", OP_REMOVE)).to.equal(false);
    });

    it("G2: dynamic policy effect at check time", async () => {
      const fogPayload = buildRegPayload({
        nodeId: "FG-1", nodeName:"Foggy", nodeTypeStr:"Fog", publicKey:"pubFog",
        registeredBy:fogOwner.address, rpcURL:"rpcFog", registeredByNodeTypeStr:"Cloud", nodeSignature:"sigFog",
      });
      const edgePayload = buildRegPayload({
        nodeId:"ED-1", nodeName:"Edgey", nodeTypeStr:"Edge", publicKey:"pubEdge",
        registeredBy:edgeOwner.address, rpcURL:"rpcEdge", registeredByNodeTypeStr:"Cloud", nodeSignature:"sigEdge",
      });
      await reg.connect(fogOwner).registerNodePacked(fogPayload);
      await reg.connect(edgeOwner).registerNodePacked(edgePayload);

      await reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ethers.ZeroHash); // id=1
      const t0 = await nowTs();
      await reg.connect(fogOwner).issueGrant("sigEdge","sigFog", 1, OP_READ | OP_REMOVE, t0 + 1800);

      await reg.connect(admin).updatePolicy(1, OP_READ, ethers.ZeroHash);

      expect(await reg.checkGrant("sigEdge","sigFog", OP_REMOVE)).to.equal(false);
      expect(await reg.checkGrant("sigEdge","sigFog", OP_READ)).to.equal(true);
    });

    it("G3: revoke/expiry and errors", async () => {
      const fogPayload = buildRegPayload({
        nodeId: "FG-1", nodeName:"Foggy", nodeTypeStr:"Fog", publicKey:"pubFog",
        registeredBy:fogOwner.address, rpcURL:"rpcFog", registeredByNodeTypeStr:"Cloud", nodeSignature:"sigFog",
      });
      const edgePayload = buildRegPayload({
        nodeId:"ED-1", nodeName:"Edgey", nodeTypeStr:"Edge", publicKey:"pubEdge",
        registeredBy:edgeOwner.address, rpcURL:"rpcEdge", registeredByNodeTypeStr:"Cloud", nodeSignature:"sigEdge",
      });
      await reg.connect(fogOwner).registerNodePacked(fogPayload);
      await reg.connect(edgeOwner).registerNodePacked(edgePayload);
      await reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ, ethers.ZeroHash); // id=1

      // revoke missing
      await expect(
        reg.connect(fogOwner).revokeGrant("sigEdge","sigFog")
      ).to.be.revertedWithCustomError(reg, "PolicyNotFound");

      // issue then revoke twice
      const t0 = await nowTs();
      await reg.connect(fogOwner).issueGrant("sigEdge","sigFog", 1, OP_READ, t0 + 300);
      await reg.connect(fogOwner).revokeGrant("sigEdge","sigFog");
      await expect(
        reg.connect(fogOwner).revokeGrant("sigEdge","sigFog")
      ).to.be.revertedWithCustomError(reg, "GrantAlreadyActive");

      // expiry path
      await reg.connect(fogOwner).issueGrant("sigEdge","sigFog", 1, OP_READ, t0 + 60);
      expect(await reg.isGrantExpired("sigEdge","sigFog")).to.equal(false);
      await ethers.provider.send("evm_increaseTime", [61]);
      await ethers.provider.send("evm_mine");
      expect(await reg.isGrantExpired("sigEdge","sigFog")).to.equal(true);
      expect(await reg.checkGrant("sigEdge","sigFog", OP_READ)).to.equal(false);
    });
  });

  // --------------------------------------------------------------------
  // DELEGATION (new functionality)
  // --------------------------------------------------------------------
  describe("Delegation flow", () => {
    beforeEach(async () => {
      // Register Fog resource (toSig = sigFog), Edge A (fromSig = sigEdgeA), Edge B (fromSig = sigEdgeB)
      const fogPayload = buildRegPayload({
        nodeId: "FG-1", nodeName: "Foggy", nodeTypeStr: "Fog",
        publicKey: "pubFog", registeredBy: fogOwner.address,
        rpcURL: "rpcFog", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigFog",
      });
      const edgeAPayload = buildRegPayload({
        nodeId: "ED-A", nodeName: "EdgeA", nodeTypeStr: "Edge",
        publicKey: "pubEdgeA", registeredBy: edgeOwner.address,
        rpcURL: "rpcEdgeA", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigEdgeA",
      });
      const edgeBPayload = buildRegPayload({
        nodeId: "ED-B", nodeName: "EdgeB", nodeTypeStr: "Edge",
        publicKey: "pubEdgeB", registeredBy: other.address,
        rpcURL: "rpcEdgeB", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigEdgeB",
      });
      await reg.connect(fogOwner).registerNodePacked(fogPayload);
      await reg.connect(edgeOwner).registerNodePacked(edgeAPayload);
      await reg.connect(other).registerNodePacked(edgeBPayload);

      // Policy Edge->Fog
      await reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ethers.ZeroHash); // id=1
    });

    it("D1: root grant without delegation cannot be delegated", async () => {
      const t0 = await nowTs();
      // resource owner issues non-delegable root grant to EdgeA
      await reg.connect(fogOwner).issueGrant("sigEdgeA","sigFog", 1, OP_READ, t0 + 600);

      // EdgeA (or its owner) cannot delegate
      await expect(
        reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ, t0 + 300)
      ).to.be.revertedWithCustomError(reg, "DelegationNotAllowed");
    });

    it("D2: root grant with delegation can be delegated; rights & expiry are subsets; depth decrements", async () => {
      const t0 = await nowTs();
      // Delegable root: depth=2
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ | OP_REMOVE, t0 + 900, true, 2);

      // Parent is active and delegable
      let gx = await reg.getGrantEx("sigEdgeA","sigFog");
      expect(gx[6]).to.equal(true);    // delegationAllowed
      expect(gx[7]).to.equal(2);       // delegationDepth

      // EdgeA's owner delegates to EdgeB with reduced rights and earlier expiry
      await expect(
        reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ, t0 + 600)
      ).to.emit(reg, "GrantDelegated");

      // Check new grant flags
      gx = await reg.getGrantEx("sigEdgeB","sigFog");
      expect(gx[0]).to.equal(1);             // same policy
      expect(gx[1]).to.equal(OP_READ);       // subset of parent
      expect(gx[6]).to.equal(true);          // delegationAllowed propagated
      expect(gx[7]).to.equal(1);             // depth decremented

      // Enforcement works
      expect(await reg.checkGrant("sigEdgeB","sigFog", OP_READ)).to.equal(true);
      expect(await reg.checkGrant("sigEdgeB","sigFog", OP_REMOVE)).to.equal(false);
    });

    it("D3: only the owner of the CURRENT grantee can delegate (NotGrantHolder)", async () => {
      const t0 = await nowTs();
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ, t0 + 600, true, 1);

      // A random account (not the owner of EdgeA) tries
      await expect(
        reg.connect(rando).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ, t0 + 500)
      ).to.be.revertedWithCustomError(reg, "NotGrantHolder");
    });

    it("D4: delegation constraints — parent expired/revoked, depth=0, ops superset, expiry beyond parent", async () => {
      const t0 = await nowTs();
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ, t0 + 60, true, 1);

      // Move past expiry -> cannot delegate
      await ethers.provider.send("evm_increaseTime", [61]);
      await ethers.provider.send("evm_mine");
      await expect(
        reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ, t0 + 50)
      ).to.be.revertedWithCustomError(reg, "InvalidExpiry");

      // --- Clear any previous active grant BEFORE re-issuing ---
      // (not strictly needed here because the first one expired, but keeps pattern consistent)

      // Re-issue with depth=0
      const t1 = await nowTs();
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ, t1 + 600, true, 0);
      await expect(
        reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ, t1 + 300)
      ).to.be.revertedWithCustomError(reg, "DelegationDepthExceeded");

      // >>> ADD THIS: revoke the active root before next re-issue <<<
      await reg.connect(fogOwner).revokeGrant("sigEdgeA","sigFog");

      // Re-issue with depth=1 and OP_READ parent; try delegating OP_REMOVE (superset)
      const t2 = await nowTs();
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ, t2 + 600, true, 1);
      await expect(
        reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_REMOVE, t2 + 300)
      ).to.be.revertedWithCustomError(reg, "EmptyOpsAllowed");

      // >>> ADD THIS: revoke again before next re-issue <<<
      await reg.connect(fogOwner).revokeGrant("sigEdgeA","sigFog");

      // Re-issue with parent expiring earlier than requested child expiry
      const t3 = await nowTs();
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ, t3 + 200, true, 1);
      await expect(
        reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ, t3 + 300)
      ).to.be.revertedWithCustomError(reg, "InvalidExpiry");

      // >>> ADD THIS: revoke again before next re-issue <<<
      await reg.connect(fogOwner).revokeGrant("sigEdgeA","sigFog");

      // Re-issue and then revoke parent -> cannot delegate
      const t4 = await nowTs();
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ, t4 + 400, true, 1);
      await reg.connect(fogOwner).revokeGrant("sigEdgeA","sigFog");
      await expect(
        reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ, t4 + 200)
      ).to.be.revertedWithCustomError(reg, "PolicyNotFound");
    });

    it("D5: policy still enforced dynamically for delegated grants", async () => {
      const t0 = await nowTs();
      // Parent has READ|REMOVE, depth=2; child gets READ|REMOVE too
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ | OP_REMOVE, t0 + 900, true, 2);
      await reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ | OP_REMOVE, t0 + 600);

      // Tighten policy to READ only -> delegated grant should lose REMOVE
      await reg.connect(admin).updatePolicy(1, OP_READ, ethers.ZeroHash);

      expect(await reg.checkGrant("sigEdgeB","sigFog", OP_REMOVE)).to.equal(false);
      expect(await reg.checkGrant("sigEdgeB","sigFog", OP_READ)).to.equal(true);

      // Deprecate policy -> access should fail
      await reg.connect(admin).deprecatePolicy(1);
      expect(await reg.checkGrant("sigEdgeB","sigFog", OP_READ)).to.equal(false);
    });

    it("D6: multi-hop delegation chain consumes depth", async () => {
      // Add third subject EdgeC
      const edgeCPayload = buildRegPayload({
        nodeId: "ED-C", nodeName: "EdgeC", nodeTypeStr: "Edge",
        publicKey: "pubEdgeC", registeredBy: sensorOwner.address,
        rpcURL: "rpcEdgeC", registeredByNodeTypeStr: "Cloud", nodeSignature: "sigEdgeC",
      });
      await reg.connect(sensorOwner).registerNodePacked(edgeCPayload);

      const t0 = await nowTs();
      // Root: depth=2 from A -> Fog
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ | OP_REMOVE, t0 + 900, true, 2);

      // A -> B (depth becomes 1)
      await reg.connect(edgeOwner).delegateGrant("sigEdgeA","sigFog","sigEdgeB", OP_READ | OP_REMOVE, t0 + 700);
      let gx = await reg.getGrantEx("sigEdgeB","sigFog");
      expect(gx[7]).to.equal(1);

      // B owner is 'other'; B -> C (depth becomes 0)
      await reg.connect(other).delegateGrant("sigEdgeB","sigFog","sigEdgeC", OP_READ, t0 + 500);
      gx = await reg.getGrantEx("sigEdgeC","sigFog");
      expect(gx[7]).to.equal(0);

      // C cannot delegate further
      await expect(
        reg.connect(sensorOwner).delegateGrant("sigEdgeC","sigFog","sigEdgeA", OP_READ, t0 + 400)
      ).to.be.revertedWithCustomError(reg, "DelegationDepthExceeded");

      // Enforcement OK for C (READ only)
      expect(await reg.checkGrant("sigEdgeC","sigFog", OP_READ)).to.equal(true);
      expect(await reg.checkGrant("sigEdgeC","sigFog", OP_REMOVE)).to.equal(false);
    });

    it("D7: getGrantEx reflects flags; getGrant keeps legacy shape", async () => {
      const t0 = await nowTs();
      await reg.connect(fogOwner).issueGrantDelegable("sigEdgeA","sigFog", 1, OP_READ, t0 + 600, true, 1);

      const g = await reg.getGrant("sigEdgeA","sigFog");
      expect(g[0]).to.equal(1);
      expect(g[1]).to.equal(OP_READ);
      expect(g[4]).to.equal(true);
      expect(g[5]).to.equal(false);

      const gx = await reg.getGrantEx("sigEdgeA","sigFog");
      expect(gx[6]).to.equal(true);  // delegationAllowed
      expect(gx[7]).to.equal(1);     // delegationDepth
    });
  });
});

// --------------------------------------------------------------------
// MULTISIG (createPolicy gating)
// --------------------------------------------------------------------
// --------------------------------------------------------------------
// MULTISIG (createPolicy gating) — self-contained
// --------------------------------------------------------------------
describe("Multisig — createPolicy gating", () => {
  let reg;
  let admin, fogOwner, edgeOwner, sensorOwner, other, rando;
  const ROLE = { Unknown: 0, Cloud: 1, Fog: 2, Edge: 3, Sensor: 4, Actuator: 5 };
  const OP_READ   = 1 << 0;
  const OP_REMOVE = 1 << 3;
  let ctxSchema;

  beforeEach(async () => {
    [admin, fogOwner, edgeOwner, sensorOwner, other, rando] = await ethers.getSigners();
    const Reg = await ethers.getContractFactory("NodeRegistry", admin);
    reg = await Reg.deploy();
    await reg.waitForDeployment();
    ctxSchema = ethers.ZeroHash;
  });

  it("M1: only admin can configure multisig; mode on/off; add/remove approvers; set threshold", async () => {
    await expect(reg.connect(fogOwner).setMsigMode(true))
      .to.be.revertedWithCustomError(reg, "NotPolicyAdmin");
    await expect(reg.connect(fogOwner).addMsigApprover(edgeOwner.address))
      .to.be.revertedWithCustomError(reg, "NotPolicyAdmin");
    await expect(reg.connect(fogOwner).removeMsigApprover(edgeOwner.address))
      .to.be.revertedWithCustomError(reg, "NotPolicyAdmin");
    await expect(reg.connect(fogOwner).setMsigThreshold(1))
      .to.be.revertedWithCustomError(reg, "NotPolicyAdmin");

    await reg.connect(admin).setMsigMode(true);
    expect(await reg.msigRequired()).to.equal(true);

    await reg.connect(admin).addMsigApprover(fogOwner.address);
    await reg.connect(admin).addMsigApprover(edgeOwner.address);
    expect(await reg.msigApprover(fogOwner.address)).to.equal(true);
    expect(await reg.msigApprover(edgeOwner.address)).to.equal(true);
    expect(await reg.msigApproverCount()).to.equal(2);

    await expect(reg.connect(admin).setMsigThreshold(0))
      .to.be.revertedWithCustomError(reg, "MsigBadThreshold");
    await expect(reg.connect(admin).setMsigThreshold(3))
      .to.be.revertedWithCustomError(reg, "MsigBadThreshold");

    await reg.connect(admin).setMsigThreshold(2);
    expect(await reg.msigThreshold()).to.equal(2);

    await reg.connect(admin).removeMsigApprover(edgeOwner.address);
    expect(await reg.msigApprover(edgeOwner.address)).to.equal(false);
    expect(await reg.msigApproverCount()).to.equal(1);
    expect(await reg.msigThreshold()).to.equal(1); // auto-capped

    await reg.connect(admin).setMsigMode(false);
    expect(await reg.msigRequired()).to.equal(false);
  });

  it("M2: gating works — need k approvals before createPolicy; approvals consume per-action", async () => {
    await reg.connect(admin).setMsigMode(true);
    await reg.connect(admin).addMsigApprover(fogOwner.address);
    await reg.connect(admin).addMsigApprover(edgeOwner.address);
    await reg.connect(admin).setMsigThreshold(2);

    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema)
    ).to.be.revertedWithCustomError(reg, "MsigNotEnoughApprovals");

    await reg.connect(fogOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema);
    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema)
    ).to.be.revertedWithCustomError(reg, "MsigNotEnoughApprovals");

    await reg.connect(edgeOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema);
    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema)
    ).to.emit(reg, "PolicyCreated");

    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema)
    ).to.be.revertedWithCustomError(reg, "MsigNotEnoughApprovals");

    await reg.connect(fogOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema);
    await reg.connect(edgeOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema);
    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema)
    ).to.emit(reg, "PolicyCreated");
  });

  it("M3: only approvers can approve; duplicate approvals are blocked", async () => {
    await reg.connect(admin).setMsigMode(true);
    await reg.connect(admin).addMsigApprover(fogOwner.address);
    await reg.connect(admin).addMsigApprover(edgeOwner.address);
    await reg.connect(admin).setMsigThreshold(2);

    await expect(
      reg.connect(rando).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ, ctxSchema)
    ).to.be.revertedWithCustomError(reg, "MsigNotApprover");

    await reg.connect(fogOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ, ctxSchema);
    await expect(
      reg.connect(fogOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ, ctxSchema)
    ).to.be.revertedWithCustomError(reg, "MsigAlreadyApproved");
  });

  it("M4: turning msig off restores legacy behavior (no approvals needed)", async () => {
    await reg.connect(admin).setMsigMode(true);
    await reg.connect(admin).addMsigApprover(fogOwner.address);
    await reg.connect(admin).addMsigApprover(edgeOwner.address);
    await reg.connect(admin).setMsigThreshold(2);

    await reg.connect(admin).setMsigMode(false); // legacy path
    await expect(
      reg.connect(admin).createPolicy(ROLE.Sensor, ROLE.Actuator, OP_READ, ctxSchema)
    ).to.emit(reg, "PolicyCreated");
  });

  it("M5: approvals are for the exact action key; different params require fresh approvals", async () => {
    await reg.connect(admin).setMsigMode(true);
    await reg.connect(admin).addMsigApprover(fogOwner.address);
    await reg.connect(admin).addMsigApprover(edgeOwner.address);
    await reg.connect(admin).setMsigThreshold(2);

    await reg.connect(fogOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ, ctxSchema);
    await reg.connect(edgeOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ, ctxSchema);
    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ, ctxSchema)
    ).to.emit(reg, "PolicyCreated");

    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema)
    ).to.be.revertedWithCustomError(reg, "MsigNotEnoughApprovals");

    await reg.connect(fogOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema);
    await reg.connect(edgeOwner).approveCreatePolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema);
    await expect(
      reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, OP_READ | OP_REMOVE, ctxSchema)
    ).to.emit(reg, "PolicyCreated");
  });
});