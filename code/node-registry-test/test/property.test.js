// Property-based correspondence tests: random operation sequences against the
// deployed NodeRegistry contract, checking the Section II properties after
// every step. A failure prints the seed and the operation trace so it can be
// replayed.
//
//   P1  token uniqueness      -- one storage slot per (subject, object, policy)
//   P2b delegation monotonicity at evaluation -- if checkGrant accepts op for a
//       token, op is in every ancestor's ops and the token does not outlive any
//       ancestor
//   P3  authorization correctness -- if checkGrant accepts op, op is in the
//       token's ops, in the policy's current ops, and in the root token's ops
const { expect } = require("chai");
const { ethers, network } = require("hardhat");

const ROLE = { Fog: 2, Edge: 3 };
const OPS = [1 << 0, 1 << 1];          // READ, WRITE
const ALL_OPS = OPS[0] | OPS[1];
const SEQUENCES = Number(process.env.PROP_SEQUENCES || 25);
const STEPS = Number(process.env.PROP_STEPS || 30);
const BASE_SEED = Number(process.env.PROP_SEED || 20261021);

// Small deterministic PRNG (mulberry32) so every failure is replayable.
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function regPayload(nodeId, nodeTypeStr, signer, sig) {
  return new ethers.AbiCoder().encode(
    ["string", "string", "string", "string", "address", "string", "string", "string"],
    [nodeId, nodeId, nodeTypeStr, `pk-${nodeId}`, signer.address, `http://${nodeId}`, "Cloud", sig]
  );
}

const grantKey = (from, to, pid) =>
  ethers.keccak256(new ethers.AbiCoder().encode(["string", "string", "uint256"], [from, to, pid]));

describe("NodeRegistry property-based correspondence (P1, P2b, P3)", function () {
  this.timeout(0);

  it(`holds over ${SEQUENCES} random sequences of ${STEPS} steps`, async () => {
    for (let seq = 0; seq < SEQUENCES; seq++) {
      const seed = BASE_SEED + seq;
      const rnd = prng(seed);
      const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
      const trace = [];

      const [admin, fogOwner, ownA, ownB, ownC] = await ethers.getSigners();
      const reg = await (await ethers.getContractFactory("NodeRegistry", admin)).deploy();
      await reg.waitForDeployment();
      await reg.connect(fogOwner).registerNodePacked(regPayload("FG-1", "Fog", fogOwner, "sigFog"));
      const subjects = [
        { sig: "sigA", owner: ownA }, { sig: "sigB", owner: ownB }, { sig: "sigC", owner: ownC },
      ];
      await reg.connect(ownA).registerNodePacked(regPayload("ED-A", "Edge", ownA, "sigA"));
      await reg.connect(ownB).registerNodePacked(regPayload("ED-B", "Edge", ownB, "sigB"));
      await reg.connect(ownC).registerNodePacked(regPayload("ED-C", "Edge", ownC, "sigC"));
      await reg.connect(admin).createPolicy(ROLE.Edge, ROLE.Fog, ALL_OPS, ethers.ZeroHash);
      const PID = 1;

      const now = async () => (await ethers.provider.getBlock("latest")).timestamp;

      async function attempt(label, fn) {
        try { await fn(); trace.push(`${label} ok`); }
        catch (e) { trace.push(`${label} reverted`); }
      }

      async function checkInvariants(step) {
        const t = await now();
        const policy = await reg.getPolicy(PID);
        const seenKeys = new Set();
        for (const s of subjects) {
          const key = grantKey(s.sig, "sigFog", PID);
          // P1: one storage slot per (subject, object, policy) -- distinct keys
          expect(seenKeys.has(key), "P1 duplicate slot").to.equal(false);
          seenKeys.add(key);
          const g = await reg.grants(key);
          for (const op of OPS) {
            const accepted = await reg.checkGrant(s.sig, "sigFog", PID, op);
            if (!accepted) continue;
            const ctx = `seed=${seed} step=${step} subject=${s.sig} op=${op}\n${trace.join("\n")}`;
            // P3: op in token ops and in the policy's current ops
            expect((Number(g.opsSubset) & op) !== 0, `P3 token ops\n${ctx}`).to.equal(true);
            expect((Number(policy.opsAllowed) & op) !== 0, `P3 policy ops\n${ctx}`).to.equal(true);
            expect(Number(g.expiresAt) >= t, `P3 unexpired\n${ctx}`).to.equal(true);
            // P2b + P3 root: walk the recorded ancestors
            let ancId = g.parentTokenId;
            let hops = 0;
            let rootOps = Number(g.opsSubset);
            while (ancId !== ethers.ZeroHash && hops < 10) {
              const a = await reg.grants(ancId);
              expect((Number(a.opsSubset) & op) !== 0, `P2b ancestor ops\n${ctx}`).to.equal(true);
              expect(Number(g.expiresAt) <= Number(a.expiresAt), `P2b outlives ancestor\n${ctx}`).to.equal(true);
              rootOps = Number(a.opsSubset);
              ancId = a.parentTokenId;
              hops++;
            }
            expect((rootOps & op) !== 0, `P3 root ops\n${ctx}`).to.equal(true);
          }
        }
      }

      for (let step = 0; step < STEPS; step++) {
        const r = rnd();
        const t = await now();
        const s = pick(subjects);
        const ops = pick([OPS[0], OPS[1], ALL_OPS]);
        // A small set of expiries makes short/long collisions between parent
        // and child likely, which is where lifecycle edge cases live.
        const exp = t + pick([60, 120, 600, 1200]);
        const depth = Math.floor(rnd() * 3);
        if (r < 0.30) {
          await attempt(`issue(${s.sig},ops=${ops},exp+${exp - t},d=${depth})`, () =>
            reg.connect(fogOwner).issueGrantDelegable(s.sig, "sigFog", PID, ops, exp, depth > 0, depth));
        } else if (r < 0.60) {
          const p = pick(subjects);
          const c = pick(subjects.filter((x) => x !== p));
          // Guided generation: most of the time derive parameters from the
          // current parent so the delegation is valid and chains get built;
          // otherwise use random parameters to exercise the guards.
          const pg = await reg.grants(grantKey(p.sig, "sigFog", PID));
          let dOps = ops, dExp = exp, dDepth = depth;
          if (rnd() < 0.8 && Number(pg.expiresAt) > t + 1 && Number(pg.depthDel) > 0) {
            dOps = Number(pg.opsSubset) & pick([OPS[0], OPS[1], ALL_OPS]) || Number(pg.opsSubset);
            dExp = t + 1 + Math.floor(rnd() * (Number(pg.expiresAt) - t - 1));
            dDepth = Math.floor(rnd() * Number(pg.depthDel));
          }
          await attempt(`delegate(${p.sig}->${c.sig},ops=${dOps},exp+${dExp - t},d=${dDepth})`, () =>
            reg.connect(p.owner).issueTokenDelegable(p.sig, "sigFog", c.sig, PID, dOps, dExp, dDepth));
        } else if (r < 0.72) {
          await attempt(`revoke(${s.sig})`, () => reg.connect(fogOwner).revokeGrant(s.sig, "sigFog", PID));
        } else if (r < 0.80) {
          const dt = 1 + Math.floor(rnd() * 60);
          await network.provider.send("evm_increaseTime", [dt]);
          await network.provider.send("evm_mine", []);
          trace.push(`tick(+${dt})`);
        } else if (r < 0.85) {
          const newOps = pick([OPS[0], OPS[1], ALL_OPS]);
          await attempt(`updatePolicy(ops=${newOps})`, () =>
            reg.connect(admin).updatePolicy(PID, newOps, ethers.ZeroHash));
        } else {
          // Re-attach: for some existing delegated child, its parent's holder
          // re-delegates onto it with a short expiry (the path that re-pins the
          // child to the parent's current generation).
          let done = false;
          for (const c of subjects) {
            const g = await reg.grants(grantKey(c.sig, "sigFog", PID));
            if (g.parentTokenId === ethers.ZeroHash || done) continue;
            const p = subjects.find((x) => grantKey(x.sig, "sigFog", PID) === g.parentTokenId);
            if (!p) continue;
            done = true;
            await attempt(`reattach(${p.sig}->${c.sig},ops=${g.opsSubset},exp+60,d=0)`, () =>
              reg.connect(p.owner).issueTokenDelegable(p.sig, "sigFog", c.sig, PID, Number(g.opsSubset), t + 60, 0));
          }
          if (!done) trace.push("reattach(none)");
        }
        await checkInvariants(step);
      }
    }
  });
});
