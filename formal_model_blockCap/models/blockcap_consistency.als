/*
 * CONSISTENCY CHECKS for Section II statements found unchecked by the audit.
 * Generated from models/blockcap_final.als (unchanged; SHA-256 90b02aed...f0ad35):
 * the text below is that file verbatim, followed by
 * additional assertions at the end. The frozen model and its results are not modified.
 */
/*
 * FINAL MODEL (frozen for the end-to-end run). Section II with the three
 * candidate fixes; not the manuscript as written. Commands are not part of
 * this file: tools/run_suite.py appends one command per job from
 * suites/*.json, so every result names its exact scope.
 * Differs from blockcap_system_model.als where marked "FIX n" and adds the
 * event record Ev (bookkeeping only; it does not constrain behaviour):
 *   FIX 1 (finding C): Auth includes the ancestor-walk conjunct (authFixed).
 *   FIX 2 (finding B): issueGrant on an active token may only narrow ops.
 *   FIX 3 (finding A): Property 2 restated (a) at derivation time and
 *                      (b) over the chain as evaluated by the ancestor walk.
 *
 * BlockCap -- Alloy 6 model of the System Model (Section II) of the manuscript
 * paper/main_access.tex, lines 235-421 (identical text in paper/main.tex).
 *
 * The model encodes Section II AS WRITTEN, not NodeRegistry.sol. Each element
 * below cites the manuscript construct it encodes. Where Section II leaves
 * something unspecified, the choice made here is marked "MODELING CHOICE".
 *
 * Configuration T = (N, D, P, Phi, R, Gamma):
 *   N      -> sig Node          (id = atom identity, role, own)
 *   D      -> sig Policy        (role_i, role_j, ops, res; f_approve abstracted)
 *   P      -> sig Slot          (one slot per (sub, obj, policy) = P^d_ij)
 *   Phi    -> pred valid        (Eq. eq:phi)
 *   R      -> implicit: pairs (n_i, n_j) for which a slot exists
 *   Gamma  -> pred gamma        (Eqs. eq:uniq and eq:mono)
 *   Auth   -> pred authFixed    (Eq. eq:auth plus the ancestor walk, FIX 1)
 */
module blockcap_consistency

-- ---------------------------------------------------------------------------
-- Static structure
-- ---------------------------------------------------------------------------

sig Role {}
sig Op {}
sig Res {}
sig Principal {}

abstract sig Bool {}
one sig True, False extends Bool {}

-- N: n_i = (id_i, role_i, ...), with owner own(n_i) fixed at registration.
-- MODELING CHOICE: registration is not modeled; every Node is registered
-- (Assumption asm:issue requires "both nodes are registered").
sig Node {
  role : one Role,
  own  : one Principal
}

-- D: d = (role_i, role_j, ops, res, f_approve(S,t)).
-- f_approve is abstracted: policy changes are admitted actions (see below).
sig Policy {
  fromRole : one Role,
  toRole   : one Role,
  var pops : set Op,          -- d.ops, mutable ("narrowed or widened")
  res      : one Res
}
var sig Dep in Policy {}      -- D_dep: deprecated policies

-- P^d_ij: a single slot per (sub, obj, policy)  (Assumption as:slot).
-- p_ij = (sub, obj, d_n, ops, dlg, delta, t_iss, t_exp, iss, rev)
-- plus the generation counter and parent link of Assumption as:slot.
sig Slot {
  sub        : one Node,
  obj        : one Node,
  pol        : one Policy,
  var tops   : set Op,        -- p.ops
  var texp   : one Int,       -- p.t_exp
  var depth  : one Int,       -- p.delta
  var parent : lone Slot,     -- p' < p  (recorded on-chain, not a token field)
  var gen    : one Int,       -- generation of this slot
  var pgen   : one Int        -- generation of the parent recorded at derivation
}
var sig Iss in Slot {}        -- p.iss = 1
var sig Rev in Slot {}        -- p.rev = 1
var sig Dlg in Slot {}        -- p.dlg = 1

-- Single slot per (pair, policy): Assumption as:slot.
fact singleSlot {
  all disj s1, s2: Slot |
    not (s1.sub = s2.sub and s1.obj = s2.obj and s1.pol = s2.pol)
}

-- Abstract clock for "now" in Phi.
one sig Clock { var now : one Int }

-- Event record (bookkeeping only): which action the current step performs,
-- by whom, and on which slot. Used by the authority checks A1-A4.
enum Kind { IssueK, DelegateK, RevokeK, PolicyK }
one sig Ev {
  var actor  : lone Principal,
  var kind   : lone Kind,
  var target : lone Slot,
  var src    : lone Slot
}
pred noEvent { no Ev.actor and no Ev.kind and no Ev.target and no Ev.src }

-- ---------------------------------------------------------------------------
-- Predicates of Section II
-- ---------------------------------------------------------------------------

-- Phi(p) == iss=1 /\ rev=0 /\ now <= t_exp /\ d_n not in D_dep   (eq:phi)
pred valid[s: Slot] {
  s in Iss
  s not in Rev
  Clock.now <= s.texp
  s.pol not in Dep
}

fun pairSlots[i, j: Node] : set Slot { { s: Slot | s.sub = i and s.obj = j } }

-- Gamma(n_i, n_j): uniqueness (eq:uniq) and monotonicity (eq:mono) for the
-- tokens of the pair. MODELING CHOICE: eq:mono is applied to the recorded
-- parent of every token of the pair.
pred gamma[i, j: Node] {
  all d: Policy | lone s: pairSlots[i, j] | s.pol = d and valid[s]
  all s: pairSlots[i, j] | some s.parent implies {
    s.tops in s.parent.tops
    s.texp <= s.parent.texp
    s.depth < s.parent.depth
  }
}

-- The evaluation the prose describes but Eq. eq:auth does not contain:
-- "The authorization check intersects the requested operation with every
-- current ancestor's operation set" (Section II) and the ancestor walk of
-- Remark rem:revoke / rem:reissue (revoked, expired, unissued, generation).
pred ancestorsOK[s: Slot, op: Op] {
  all x: s.*parent | some x.parent implies {
    let a = x.parent | {
      a in Iss
      a not in Rev
      Clock.now <= a.texp
      x.pgen = a.gen
      op in a.tops
    }
  }
}
-- FIX 1 (finding C): Eq. eq:auth extended with the ancestor-walk conjunct.
pred authFixed[i: Node, op: Op, j: Node] {
  gamma[i, j]
  some s: pairSlots[i, j] |
    valid[s] and op in s.tops and op in s.pol.pops and ancestorsOK[s, op]
}

-- ---------------------------------------------------------------------------
-- Initial state
-- ---------------------------------------------------------------------------

fact init {
  no Iss
  no Rev
  no Dlg
  no Dep
  Clock.now = 0
  all s: Slot {
    no s.tops
    s.texp = 0
    s.depth = 0
    no s.parent
    s.gen = 0
    s.pgen = 0
  }
}

-- ---------------------------------------------------------------------------
-- Frame helpers
-- ---------------------------------------------------------------------------

pred slotUnchanged[s: Slot] {
  s.tops' = s.tops
  s.texp' = s.texp
  s.depth' = s.depth
  s.parent' = s.parent
  s.gen' = s.gen
  s.pgen' = s.pgen
  (s in Iss') iff (s in Iss)
  (s in Rev') iff (s in Rev)
  (s in Dlg') iff (s in Dlg)
}
pred policiesUnchanged { pops' = pops and Dep' = Dep }
pred clockUnchanged    { Clock.now' = Clock.now }

-- ---------------------------------------------------------------------------
-- Lifecycle operations (Assumptions as:slot, asm:issue, as:deleg)
-- ---------------------------------------------------------------------------

-- issueGrant(n_i, n_j, d_n, ops)  -- Assumption asm:issue
-- The new operation set `ops` is the post-state value s.tops' (first-order
-- encoding of the set-valued argument).
pred issue[c: Principal, s: Slot, t: Int, d: Int, b: Bool] {
  Ev.actor = c and Ev.kind = IssueK and Ev.target = s and no Ev.src
  -- guards
  c = s.obj.own
  s.sub.role = s.pol.fromRole
  s.obj.role = s.pol.toRole
  s.pol not in Dep
  some s.tops'
  s.tops' in s.pol.pops
  t > Clock.now
  d >= 0
  (b = True) iff (s in Dlg')
  valid[s] implies {
    -- adjust in place: "ops is replaced, subject to the same policy bound;
    -- t_exp may only move forward, and not beyond that of the token's parent
    -- where one exists; and the remaining delegation depth may not be
    -- increased."
    some s.parent implies t <= s.parent.texp
    d <= s.depth
    s.tops' in s.tops                  -- FIX 2 (finding B): may only narrow
    s.texp' = (t > s.texp implies t else s.texp)
    s.depth' = d
    s.parent' = s.parent
    s.gen' = s.gen
    s.pgen' = s.pgen
    (s in Iss') and (s not in Rev')
  } else {
    -- "If P^{d_n}_ij contains no valid token, a new one is created."
    -- Remark rem:reissue: a lapsed token is re-issued as a fresh root.
    s.texp' = t
    s.depth' = d
    no s.parent'
    s.gen' = s.gen.plus[1]
    s.pgen' = 0
    (s in Iss') and (s not in Rev')
  }
  all x: Slot - s | slotUnchanged[x]
  policiesUnchanged
  clockUnchanged
}

-- delegateGrant(p, n_k, ops', t'_exp)  -- Assumption as:deleg
-- ops' is the post-state value ch.tops' (first-order encoding).
pred delegate[c: Principal, p: Slot, k: Node, t: Int] {
  c = p.sub.own                      -- invoked by the holder of p
  valid[p]
  p in Dlg
  p.depth > 0
  Clock.now < t
  t <= p.texp
  some ch: Slot | {
    Ev.actor = c and Ev.kind = DelegateK and Ev.target = ch and Ev.src = p
    ch.sub = k and ch.obj = p.obj and ch.pol = p.pol
    not valid[ch]                     -- no q in P^{d_n}_kj with Phi(q)
    ch.tops' in p.tops                -- ops' subset of p.ops
    ch.tops' in p.pol.pops            -- ops' subset of p.d_n.ops
    ch.texp' = t
    ch.depth' = p.depth.minus[1]      -- p'.delta = p.delta - 1
    ch.parent' = p                    -- p' < p
    ch.gen' = ch.gen.plus[1]
    ch.pgen' = p.gen                  -- records generation of p
    (ch in Iss') and (ch not in Rev')
    (ch in Dlg') iff (p in Dlg)       -- p'.dlg = p.dlg
    all x: Slot - ch | slotUnchanged[x]
  }
  policiesUnchanged
  clockUnchanged
}

-- revokeGrant  -- object owner only (Assumption as:slot names the operation;
-- MODELING CHOICE: caller is own(n_j), as for issuance).
pred revoke[c: Principal, s: Slot] {
  Ev.actor = c and Ev.kind = RevokeK and Ev.target = s and no Ev.src
  c = s.obj.own
  s in Iss
  s not in Rev
  Rev' = Rev + s
  Iss' = Iss
  Dlg' = Dlg
  all x: Slot | x.tops' = x.tops and x.texp' = x.texp and x.depth' = x.depth
                and x.parent' = x.parent and x.gen' = x.gen and x.pgen' = x.pgen
  policiesUnchanged
  clockUnchanged
}

-- Policy administration: "d.ops may be narrowed or widened, and d may be
-- deprecated". f_approve is abstracted: these are admitted transitions.
pred setPolicyOps[d: Policy] {
  no Ev.actor and Ev.kind = PolicyK and no Ev.target and no Ev.src
  d not in Dep
  some d.pops'
  all x: Policy - d | x.pops' = x.pops
  Dep' = Dep
  all x: Slot | slotUnchanged[x]
  clockUnchanged
}
pred deprecate[d: Policy] {
  no Ev.actor and Ev.kind = PolicyK and no Ev.target and no Ev.src
  d not in Dep
  Dep' = Dep + d
  pops' = pops
  all x: Slot | slotUnchanged[x]
  clockUnchanged
}

-- Time advances.
pred tick {
  noEvent
  Clock.now' = Clock.now.plus[1]
  all x: Slot | slotUnchanged[x]
  policiesUnchanged
}

pred stutter {
  noEvent
  all x: Slot | slotUnchanged[x]
  policiesUnchanged
  clockUnchanged
}

fact transitions {
  always (
    stutter
    or tick
    or (some c: Principal, s: Slot, t: Int, d: Int, b: Bool | issue[c, s, t, d, b])
    or (some c: Principal, p: Slot, k: Node, t: Int | delegate[c, p, k, t])
    or (some c: Principal, s: Slot | revoke[c, s])
    or (some d: Policy | setPolicyOps[d])
    or (some d: Policy | deprecate[d])
  )
}

-- ---------------------------------------------------------------------------
-- Assertions (commands are appended per job by tools/run_suite.py)
-- ---------------------------------------------------------------------------

-- Property prop:uniq (Token uniqueness) / Eq. eq:uniq.
assert P1_TokenUniqueness {
  always all i, j: Node, d: Policy |
    lone s: pairSlots[i, j] | s.pol = d and valid[s]
}

-- Original Property prop:mono over stored state. Kept for comparison: it is
-- expected to FAIL while narrowing a parent in place is allowed (finding A).
assert P2_StoredState {
  always all s: Slot, a: s.^parent |
    (s in Iss) implies (s.tops in a.tops and s.texp <= a.texp and s.depth < a.depth)
}

-- FIX 3a: Property 2 at derivation time. In the state right after a slot is
-- derived (new generation with a parent link), it is bounded by its parent.
assert P2_AtDerivation {
  always all ch: Slot |
    (ch.gen' != ch.gen and some ch.parent') implies
      after (ch.tops in ch.parent.tops and ch.texp <= ch.parent.texp
             and ch.depth < ch.parent.depth)
}

-- FIX 3b: Property 2 over the chain as evaluated by the ancestor walk.
assert P2_EvaluatedChain {
  always all s: Slot, op: Op |
    (valid[s] and op in s.tops and ancestorsOK[s, op]) implies
      (all a: s.^parent | op in a.tops and s.texp <= a.texp)
}

-- Property prop:sound with the fixed Auth (FIX 1).
assert P3_AuthCorrectness {
  always all i, j: Node, op: Op | authFixed[i, op, j] implies
    some s: pairSlots[i, j] | valid[s] and op in s.tops and op in s.pol.pops
      and (all r: s.^parent | no r.parent implies op in r.tops)
}

-- Remark rem:revoke with the fixed Auth.
assert R_Revocation {
  always all s: Slot, op: Op |
    (some (s.^parent & Rev)) implies
      not (valid[s] and op in s.tops and op in s.pol.pops and ancestorsOK[s, op])
}

-- Remark rem:reissue as an outcome, independent of the generation counter:
-- if, since s was last derived, its parent has at some point been invalid,
-- no later re-issue of the parent makes s authorized again.
pred derivedNow[s: Slot] { before (s.gen' != s.gen and some s.parent') }
assert R_ReissueOutcome {
  always all s: Slot, op: Op |
    (some s.parent and ((not derivedNow[s]) since (not valid[s.parent])))
      implies not (valid[s] and ancestorsOK[s, op])
}

-- Equivalence check (mutant M09): for a valid token the walk gives the same
-- verdict with and without the ancestor-expiry condition.
pred ancestorsOK_noExpiry[s: Slot, op: Op] {
  all x: s.*parent | some x.parent implies {
    let a = x.parent | {
      a in Iss
      a not in Rev
      x.pgen = a.gen
      op in a.tops
    }
  }
}
assert WalkExpiryRedundant {
  always all s: Slot, op: Op |
    valid[s] implies (ancestorsOK[s, op] iff ancestorsOK_noExpiry[s, op])
}

-- FIX 2 as an outcome: within one generation of a slot its operation set
-- never grows. genStart[s] holds in the state right after s got its current
-- generation (fresh issue or derivation).
pred genStart[s: Slot] { before (s.gen' != s.gen) }
assert F2_OpsNeverGrowWithinGeneration {
  always all s: Slot, op: Op |
    (valid[s] and op in s.tops) implies ((op in s.tops) since genStart[s])
}

-- Authority (who may act). changed[s]: some field of s differs in the next state.
pred changed[s: Slot] { not slotUnchanged[s] }
-- A1: a token is changed by anyone other than its object's owner only through
--     a delegation (issue / adjust / revoke are owner-only).
assert A1_NonDelegationChangesOnlyByObjectOwner {
  always all s: Slot | (changed[s] and Ev.kind != DelegateK) implies Ev.actor = s.obj.own
}
-- A2: a delegation into s is performed by the holder of s's new parent.
assert A2_DelegationOnlyByParentHolder {
  always all s: Slot | (changed[s] and Ev.kind = DelegateK) implies
    (Ev.actor = Ev.src.sub.own and s.parent' = Ev.src)
}
-- A3: only the object owner can revoke.
assert A3_RevocationOnlyByObjectOwner {
  always all s: Slot | (s not in Rev and s in Rev') implies Ev.actor = s.obj.own
}
-- A4: every token change is attributed to the step's target (frame conditions).
assert A4_NoUnattributedChange {
  always all s: Slot | changed[s] implies Ev.target = s
}

-- Roles. R1: a valid root token matches its policy's roles (asm:issue guard).
assert R1_RootTokensMatchPolicyRoles {
  always all s: Slot | (valid[s] and no s.parent) implies
    (s.sub.role = s.pol.fromRole and s.obj.role = s.pol.toRole)
}
-- R2: the same for delegated tokens. Section II's as:deleg has no role guard,
-- so this is expected to FAIL (finding D).
assert R2_DelegatedTokensMatchPolicyRoles {
  always all s: Slot | (valid[s] and some s.parent) implies
    (s.sub.role = s.pol.fromRole and s.obj.role = s.pol.toRole)
}

-- ---------------------------------------------------------------------------
-- Scenario predicates for run commands (non-vacuity and consistency)
-- ---------------------------------------------------------------------------
pred Reach_DelegationChainDepth2 {
  eventually some s: Slot | valid[s] and some s.parent.parent and valid[s.parent]
}
pred Reach_RevokedParentWithLiveChild {
  eventually some s: Slot | valid[s] and some (s.parent & Rev)
}
pred Reach_ParentReissuedAfterLapse {
  eventually some s: Slot |
    some s.parent and valid[s.parent] and ((not derivedNow[s]) since (not valid[s.parent]))
}
pred Reach_RoleMismatchDelegation {
  eventually some s: Slot | valid[s] and some s.parent and s.sub.role != s.pol.fromRole
}
-- Consistency (Grisham-style): one trace with a depth-2 chain, a revocation,
-- a fresh re-issue (generation 2) and a policy change.
pred Rich_AllMechanismsInOneTrace {
  eventually (some s: Slot | valid[s] and some s.parent.parent)
  eventually (some Rev)
  eventually (some s: Slot | s.gen = 2 and no s.parent and valid[s])
  eventually (Ev.kind = PolicyK)
}

-- ===========================================================================
-- Additional assertions: Section II statements not covered by the final suite
-- ===========================================================================

-- "narrowing or deprecating a policy takes effect immediately for every token
-- under it": once op leaves d.ops, no token under d authorizes op.
assert C1_PolicyNarrowingImmediate {
  always all d: Policy, op: Op | (op in d.pops and op not in d.pops') implies
    after (all s: Slot | s.pol = d implies not (valid[s] and op in s.tops and op in s.pol.pops))
}
-- ... and once d is deprecated, no token under d is valid.
assert C2_DeprecationImmediate {
  always all d: Policy | (d not in Dep and d in Dep') implies
    after (all s: Slot | s.pol = d implies not valid[s])
}
-- Remark rem:reissue / asm:issue: an in-place adjustment (same generation)
-- retains the parent, never moves expiry backwards, never raises depth, and
-- never extends expiry beyond the parent's.
assert C3_AdjustRetainsParent {
  always all s: Slot | (s in Iss and s.gen' = s.gen) implies s.parent' = s.parent
}
assert C4_AdjustExpiryForward {
  always all s: Slot | (s in Iss and s.gen' = s.gen) implies s.texp' >= s.texp
}
assert C5_AdjustDepthNotIncreased {
  always all s: Slot | (s in Iss and s.gen' = s.gen) implies s.depth' <= s.depth
}
assert C6_AdjustNotBeyondParent {
  always all s: Slot | (s in Iss and s.gen' = s.gen and s.texp' != s.texp and some s.parent)
    implies s.texp' <= s.parent.texp
}
-- as:deleg: the derived token copies the parent's delegability flag.
assert C7_DelegationCopiesDlg {
  always all ch: Slot | (ch.gen' != ch.gen and some ch.parent') implies
    after ((ch in Dlg) iff (ch.parent in Dlg))
}
-- Reworded Gamma text: a request is denied whenever Eq. (eq:mono) no longer
-- holds for a token of the pair.
assert C8_BrokenMonotonicityDenies {
  always all i, j: Node, op: Op |
    (some s: pairSlots[i, j] | some s.parent and
       not (s.tops in s.parent.tops and s.texp <= s.parent.texp and s.depth < s.parent.depth))
    implies not authFixed[i, op, j]
}
-- Non-vacuity for C3-C6: an active delegated token is adjusted in place.
pred Reach_AdjustDelegatedInPlace {
  eventually some s: Slot | s in Iss and some s.parent and s.gen' = s.gen and
    (s.tops' != s.tops or s.texp' != s.texp or s.depth' != s.depth)
}
-- Non-vacuity for C1/C2.
pred Reach_PolicyNarrowedWhileTokenValid {
  eventually some d: Policy, op: Op, s: Slot |
    s.pol = d and valid[s] and op in s.tops and op in d.pops and op not in d.pops'
}
pred Reach_DeprecationWhileTokenValid {
  eventually some s: Slot | valid[s] and s.pol not in Dep and s.pol in Dep'
}
