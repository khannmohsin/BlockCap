/*
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
 *   Auth   -> pred authEq       (Eq. eq:auth, exactly as written)
 */
module blockcap_system_model

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

-- Auth(n_i, op, n_j), Eq. eq:auth exactly as written (SigValid abstracted as
-- true for registered nodes).
pred authEq[i: Node, op: Op, j: Node] {
  gamma[i, j]
  some s: pairSlots[i, j] | valid[s] and op in s.tops and op in s.pol.pops
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
pred authWalk[i: Node, op: Op, j: Node] {
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
  d not in Dep
  some d.pops'
  all x: Policy - d | x.pops' = x.pops
  Dep' = Dep
  all x: Slot | slotUnchanged[x]
  clockUnchanged
}
pred deprecate[d: Policy] {
  d not in Dep
  Dep' = Dep + d
  pops' = pops
  all x: Slot | slotUnchanged[x]
  clockUnchanged
}

-- Time advances.
pred tick {
  Clock.now' = Clock.now.plus[1]
  all x: Slot | slotUnchanged[x]
  policiesUnchanged
}

pred stutter {
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
-- Checks
-- ---------------------------------------------------------------------------

-- Property prop:uniq (Token uniqueness) / Eq. eq:uniq.
assert P1_TokenUniqueness {
  always all i, j: Node, d: Policy |
    lone s: pairSlots[i, j] | s.pol = d and valid[s]
}

-- Property prop:mono (Delegation monotonicity), stated for p' <* p.
assert P2_DelegationMonotonicity {
  always all s: Slot, a: s.^parent |
    (s in Iss) implies (s.tops in a.tops and s.texp <= a.texp and s.depth < a.depth)
}

-- Property prop:mono restricted to the cases the evaluation actually relies
-- on: s is valid and every link up to a has a matching generation.
assert P2b_MonotonicityOnLiveChains {
  always all s: Slot, a: s.^parent |
    (valid[s] and (all x: s.*parent - a.*parent | x.pgen = x.parent.gen))
      implies (s.tops in a.tops and s.texp <= a.texp and s.depth < a.depth)
}

-- Property prop:sound (Authorization correctness) for Eq. eq:auth as written:
-- if Auth holds, op is within the token's ops, the policy's current ops, and,
-- if delegated, the ops of the token at the root of its delegation sequence.
assert P3_AuthCorrectness_EqAuth {
  always all i, j: Node, op: Op | authEq[i, op, j] implies
    some s: pairSlots[i, j] | valid[s] and op in s.tops and op in s.pol.pops
      and (all r: s.^parent | no r.parent implies op in r.tops)
}

-- Same property for the ancestor-walking evaluation described in the prose.
assert P3_AuthCorrectness_Walk {
  always all i, j: Node, op: Op | authWalk[i, op, j] implies
    some s: pairSlots[i, j] | valid[s] and op in s.tops and op in s.pol.pops
      and (all r: s.^parent | no r.parent implies op in r.tops)
}

-- Remark rem:revoke: revocation of p invalidates every descendant
-- (scopes here are far below the ten-level walk bound).
assert R_RevocationReachesDescendants_EqAuth {
  always all s: Slot, op: Op |
    (some (s.^parent & Rev)) implies not authEq[s.sub, op, s.obj]
      or (some s2: pairSlots[s.sub, s.obj] - s | valid[s2])
}
assert R_RevocationReachesDescendants_Walk {
  always all s: Slot, op: Op |
    (some (s.^parent & Rev)) implies
      not (valid[s] and op in s.tops and op in s.pol.pops and ancestorsOK[s, op])
}

-- Remark rem:reissue: a token derived from an earlier occupant of p's slot is
-- not authorized by an unrelated later re-issue of that slot.
assert R_ReissueDoesNotRevalidateStaleChild_Walk {
  always all s: Slot, op: Op |
    (some s.parent and s.pgen != s.parent.gen) implies
      not (valid[s] and ancestorsOK[s, op])
}

-- ---------------------------------------------------------------------------
-- Non-vacuity runs (the interesting states are reachable)
-- ---------------------------------------------------------------------------

run Reach_DelegationChainDepth2 {
  eventually some s: Slot | valid[s] and some s.parent.parent and valid[s.parent]
} for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps

run Reach_RevokedParentWithLiveChild {
  eventually some s: Slot | valid[s] and some (s.parent & Rev)
} for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps

check P1_TokenUniqueness
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
check P2_DelegationMonotonicity
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
check P2b_MonotonicityOnLiveChains
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
check P3_AuthCorrectness_EqAuth
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
check P3_AuthCorrectness_Walk
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
check R_RevocationReachesDescendants_EqAuth
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
check R_RevocationReachesDescendants_Walk
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
check R_ReissueDoesNotRevalidateStaleChild_Walk
  for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps
