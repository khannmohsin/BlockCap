# BlockCap — Alloy 6 model of the System Model (Section II)

Bounded model checking of the System Model in `paper/main_access.tex`, lines
235–421 (identical body text in `paper/main.tex`). The model encodes
Section II **as written**, not `NodeRegistry.sol`. Checking the contract
itself is a separate step (for example Halmos or Foundry invariant tests).

The manuscript is not modified by anything in this folder.

## Layout

| Path | Contents |
|---|---|
| `models/blockcap_system_model.als` | The Alloy 6 model: structure, Φ, Γ, Auth, lifecycle operations, the checks, and the non-vacuity runs |
| `tools/org.alloytools.alloy.dist.jar` | Alloy 6.2.0 (official release, 2025-01-09), SHA-256 `6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d` |
| `run_checks.sh` | Runs every command and writes `results/summary.txt` |
| `results/` | One directory per command (`cmd_<i>/`, JSON instances and counterexamples), a log per command, and `summary.txt` |

## Running

Requires Java 17 or later.

```sh
./run_checks.sh                     # all commands; writes results/summary.txt
java -jar tools/org.alloytools.alloy.dist.jar gui    # open the model in the Alloy GUI
```

How to read verdicts:
- A **run** command answers "is this scenario reachable?". SAT means an instance was found.
- A **check** command answers "does this property hold?". UNSAT means no counterexample exists within the scope; SAT means a counterexample was found, stored in `results/cmd_<i>/`.

## Mapping from Section II to the model

| Section II | Model |
|---|---|
| `T = (N, D, P, Φ, R, Γ)` | `Node`, `Policy`, `Slot`, `valid`, slot pairs, `gamma` |
| `n_i = (id_i, role_i, …)`, `own(n_i)` | `Node.role`, `Node.own` |
| `d = (role_i, role_j, ops, res, f_approve)`, `D_dep` | `Policy.fromRole/toRole/pops/res`, `Dep`; `f_approve` abstracted as admitted transitions |
| `p_ij = (sub, obj, d_n, ops, dlg, δ, t_iss, t_exp, iss, rev)` | `Slot` fields plus `Iss`, `Rev`, `Dlg` (`t_iss` is not used by any property and is omitted) |
| `P^d_ij` (one slot per pair and policy) | `fact singleSlot` |
| `p' ≺ p`, generation counter (Assumption 1) | `Slot.parent`, `Slot.gen`, `Slot.pgen` |
| Φ, Eq. (`eq:phi`) | `pred valid` |
| Γ, Eqs. (`eq:uniq`), (`eq:mono`) | `pred gamma` |
| Auth, Eq. (`eq:auth`) | `pred authEq` (exactly as written) |
| "intersects … with every current ancestor's operation set"; Remarks `rem:reissue`, `rem:revoke` | `pred authWalk` / `ancestorsOK` |
| Assumption `asm:issue` | `pred issue` |
| Assumption `as:deleg` | `pred delegate` |
| `revokeGrant` | `pred revoke` |
| "d.ops may be narrowed or widened, and d may be deprecated" | `pred setPolicyOps`, `pred deprecate` |
| `now` | `Clock.now`, advanced by `tick` |

### Modeling choices (where Section II is silent)
- **Registration** is not modeled: every node is registered, and `SigValid` is taken as true.
- **Revocation** is performed by the object owner, as for issuance.
- **`f_approve`** is abstracted: policy changes are admitted transitions, so the model does not check the multisignature mechanism.
- **Set-valued arguments** (`ops`, `ops'`, a policy's new ops) are encoded as the post-state value of the field. This is the standard first-order encoding in Alloy, and it allows every value the guards permit.

## Scope

`for 4 Node, 2 Policy, 4 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..7 steps`, with arithmetic overflow excluded (`-n`).

This is enough for a two-level delegation chain plus revocation, re-issue and policy changes. The bound is far below the ten-level ancestor walk, so the walk is modeled as the full transitive closure.

Results are **bounded**: "no counterexample" means none exists within this scope, not a proof for all sizes.

## Results (2026-10-05, Alloy 6.2.0)

Raw verdicts are in `results/summary.txt`. Each counterexample is decoded
state by state in `results/counterexample_cmd_<i>.txt`, produced from
`results/cmd_<i>_xml/` with `tools/decode_trace.py`.

| # | Command | Verdict | Meaning |
|---|---|---|---|
| 0 | Reach: depth-2 delegation chain | SAT (reachable) | Non-vacuity: chains of length 2 occur |
| 1 | Reach: revoked parent, valid child | SAT (reachable) | Non-vacuity: the revocation scenario occurs |
| 2 | **Property 1** Token uniqueness | **Holds** (no counterexample) | Structural, as the proof says: one slot per (pair, policy) |
| 3 | **Property 2** Delegation monotonicity, as stated | **Fails** | See finding A |
| 4 | Property 2 restricted to valid, generation-matched chains | **Fails** | See finding B |
| 5 | **Property 3** Authorization correctness, with Eq. (`eq:auth`) as written | **Fails** | See finding C |
| 6 | Property 3, with the ancestor walk the prose describes | **Holds** | |
| 7 | Remark `rem:revoke`, with Eq. (`eq:auth`) as written | **Fails** | See finding C |
| 8 | Remark `rem:revoke`, with the ancestor walk | **Holds** | |
| 9 | Remark `rem:reissue` (generation matching), with the walk | **Holds** | |

### Findings

**A. Property 2 does not hold as a statement about reachable states.**
(`counterexample_cmd_3.txt`)
- *Trace:* the parent `p` (depth 1) delegates a child (depth 0). The object owner then re-issues the still-valid `p` in place and lowers its depth to 0. Assumption `asm:issue` allows this: "the remaining delegation depth may not be increased", so lowering is permitted.
- *Result:* the child now has `p'.δ = p.δ`, so `p'.δ < p.δ` fails.
- *Why the proof misses it:* it relies on values "fixed at derivation", but Assumption `asm:issue` lets the parent's `ops`, `δ` and `t_exp` change in place afterwards. Property 2 holds only at the moment of derivation, not in later states.

**B. Assumption `asm:issue` lets a delegated child be widened beyond its parent.**
(`counterexample_cmd_4.txt`)
- *Trace:* a delegated child (ops ⊆ parent's {Op1}) is re-issued in place by the object owner with ops = {Op0}.
- *Why it's allowed:* Assumption `asm:issue` says "`ops` is replaced, subject to the same policy bound". The bound is the policy, not the parent.
- *Conflict with the text:* Section II's own prose says "An active grant may only narrow its operation set; an active delegated grant … may not be widened". Assumption `asm:issue` and the prose disagree. `NodeRegistry.sol` (`_issueGrantCore`, active branch) follows the prose: it reverts on any widening.

**C. Eq. (`eq:auth`) as written does not imply Property 3 or Remark `rem:revoke`.**
(`counterexample_cmd_5.txt`, `counterexample_cmd_7.txt`)
- *Trace for Property 3:* in a chain root → child → grandchild, the owner narrows the root in place to {Op0}. The grandchild still has {Op1}. Eq. (`eq:auth`) checks Γ only for the grandchild's own pair, and that pair's direct-parent containment still holds, so Auth grants Op1 even though the root no longer allows it.
- *Trace for the revocation remark:* revoking a parent leaves its child authorized under Eq. (`eq:auth`).
- *With the ancestor walk:* when Auth includes the walk described in the prose ("intersects the requested operation with every current ancestor's operation set") and in Remarks `rem:reissue` and `rem:revoke`, both properties hold (commands 6 and 8). Eq. (`eq:auth`) is missing that conjunct.

### What would make the model consistent (not applied; the manuscript is unchanged)
1. Add the ancestor-walk conjunct to Eq. (`eq:auth`) (finding C).
2. In Assumption `asm:issue`, say an active token's `ops` may only be narrowed (finding B), matching the prose and the contract.
3. Restate Property 2 as a derivation-time property, or as a property of the *evaluated* chain via the ancestor walk, rather than of stored state (finding A).

These are candidate fixes only. Each should be re-checked in this model before any manuscript change.

## Candidate fixes, checked (2026-10-05)

`models/blockcap_system_model_fixed.als` is a copy of the model with the three
candidate fixes applied; each change is marked `FIX n` in the file. The
manuscript is unchanged. Results are in `results_blockcap_system_model_fixed/summary.txt`.

| Fix | Change in the model | Addresses |
|---|---|---|
| 1 | Auth = Eq. (`eq:auth`) plus the ancestor-walk conjunct (`authFixed`): every current ancestor is issued, unrevoked, unexpired, generation-matched and contains `op` | Finding C |
| 2 | Re-issuing an active token in place may only narrow `ops` (`s.tops' in s.tops`) | Finding B |
| 3 | Property 2 restated (a) at derivation time and (b) over the chain as evaluated by the walk | Finding A |

| Check | Scope | Verdict |
|---|---|---|
| Reach: depth-2 delegation chain | main, small | Reachable |
| Reach: revoked parent with valid child | main | Reachable |
| Property 1, token uniqueness | main | **Holds** |
| Property 2 over stored state (original wording, kept for comparison) | main | Fails, as expected: narrowing a parent in place still breaks a stored-state relation |
| Property 2 at derivation time (fix 3a) | small | **Holds** |
| Property 2 over the evaluated chain (fix 3b) | small | **Holds** |
| Property 3 with fixed Auth (fix 1) | main | **Holds** |
| Remark `rem:revoke` with fixed Auth (fix 1) | main | **Holds** |
| Remark `rem:reissue` with fixed Auth | main | **Holds** |
| Re-issue in place never widens (fix 2) | small | **Holds** |

Scopes:
- *main*: 4 Node, 2 Policy, 4 Slot, 2 Op, 4 Int, 1..7 steps.
- *small*: the same with 3 Slot and 1..5 steps. This is still enough for a full root → child → grandchild chain (reachability confirmed at this scope) plus one in-place re-issue.

The three small-scope checks were stopped at the main scope after 9–48 minutes without a verdict.

**Conclusion (bounded):** with fixes 1–3, every property and remark of Section II, in its restated form, has no counterexample within scope. Property 2 cannot hold as a statement about stored state while in-place narrowing of a parent is allowed. It must be stated at derivation time or over the evaluated chain.

## Mutation testing (2026-10-05)

`tools/mutation_test.py` makes copies of the fixed model, breaks exactly one
rule in each, and runs the checks that should detect the break. Results:
`results_mutation/summary.txt` (all mutants) and `results_mutation/summary_rerun.txt`
(M08 and M10 after the re-issue check was strengthened). Scope: small.

| Mutant | Rule broken | Result |
|---|---|---|
| M01 | One slot per (pair, policy) | Killed by Property 1 |
| M02 | Re-issue may only narrow (fix 2) | Killed |
| M03 | Delegated ops ⊆ parent ops | Killed by Property 2 at derivation |
| M04 | Child expiry ≤ parent expiry | Killed by both Property 2 forms |
| M05 | Delegation decrements depth | Killed by Property 2 at derivation |
| M06 | Walk checks ancestor ops | Killed by Property 3 |
| M07 | Walk checks ancestor revocation | Killed by the revocation remark |
| M08 | Walk checks generation match | Killed by both re-issue checks |
| M09 | Walk checks ancestor expiry | **Survived: equivalent mutant.** `WalkExpiryRedundant` holds: for a valid token the walk gives the same verdict with and without this condition, because a child never outlives its parent |
| M10 | Fresh issue bumps the generation | Survived the original re-issue check; **killed** by the new outcome check `R_ReissueOutcome_Fixed` |
| M11 | Ancestor walk in Auth (fix 1) | Killed by Property 3 |

**Changes made as a result:**
- **Re-issue remark:** the generation-based check
  (`R_ReissueDoesNotRevalidateStaleChild_Fixed`) was too weak. Its premise
  ("recorded generation differs") is never true when generations are not
  bumped, so it passed without testing anything. It is superseded by
  `R_ReissueOutcome_Fixed`, which states the remark as an outcome: if a
  child's parent has been invalid at any point since the child was derived,
  no later re-issue makes the child authorized again. It holds at the small
  scope with 1..5 steps (31 min).
- **Step bound:** the lapse-and-re-issue scenario needs 4 actions, which is
  5 states. At 1..4 steps it is unreachable (`Reach_ParentReissuedAfterLapse`
  is UNSAT), so a 4-step pass would be vacuous. At 1..5 steps it is reachable
  (`Reach_ParentReissuedAfterLapse_5`).

**Observation from the 5-step trace** (`new_cmd_18`): the "re-issue" Alloy
found is a delegation **cycle**. A revoked parent's slot is refilled by a
delegation from its own child, so the two slots point to each other as
parents. Section II does not rule out such cycles. The generation check
denies both tokens, so it is safe in the model, but cycles are allowed rather
than excluded.

## Final results (frozen model, 2026-10-05/06)

**Model:** `models/blockcap_final.als`, SHA-256 `90b02aed2f82957eb44c62a63310a30fb3b559212df43a9e1b584f13d3f0ad35`.
**Tool:** Alloy 6.2.0 (jar SHA-256 `6b8c1cb5bc93bedfc7c61435c4e1ab6e688a242dc702a394628d9a9801edb78d`), openjdk version "21.0.11" 2026-04-21.
**Analysis:** bounded model checking (SAT), with arithmetic overflow excluded.

This is §II with the three fixes, plus an event record (bookkeeping only) for the authority checks. The model file contains no commands: `tools/run_suite.py` adds one command per job from `suites/*.json`, so every result is tied to an exact scope.

**Scopes:**
- *main*: `4 Node, 2 Policy, 4 Slot, 2 Op, 2 Role, 2 Res, 2 Principal, 4 Int, 1..7 steps`
- *small*: the same with `3 Slot, 1..5 steps`, the minimum that admits lapse-then-re-issue (4 actions = 5 states).

**How to reproduce:**
```sh
./run_final.sh                                   # main -> mutation -> scaling
python3 tools/run_suite.py suites/rerun.json     # completes the 3 main-suite timeouts
python3 tools/progress.py [--suite rerun]        # live progress
```

### Results (consolidated; `results_final/final_table.md`)
Source `main` = `results_final/main/`; `rerun` = `results_final/rerun/`; `timing` = `results_final/timing/`. Reruns were used for the three checks that timed out on battery power in the main suite, and to re-time checks whose main-suite time spanned system sleep. R1 was rerun at the small scope.

| Command | Kind | Scope | Result | Solve time (s) | As expected | Source |
|---|---|---|---|---|---|---|
| Reach_DelegationChainDepth2 | run | main | reachable | 25 | yes | main |
| Reach_DelegationChainDepth2_small | run | small | reachable | 12 | yes | main |
| Reach_RevokedParentWithLiveChild | run | main | reachable | 16 | yes | main |
| Reach_ParentReissuedAfterLapse | run | small | reachable | 221 | yes | main |
| Reach_RoleMismatchDelegation | run | main | reachable | 11 | yes | main |
| Rich_AllMechanismsInOneTrace | run | main | reachable | 1355 | yes | rerun |
| P1_TokenUniqueness | check | main | holds | 33 | yes | main |
| P2_StoredState | check | main | counterexample | 63 | yes | main |
| P2_AtDerivation | check | small | holds | 374 | yes | main |
| P2_EvaluatedChain | check | small | holds | 1145 | yes | main |
| P3_AuthCorrectness | check | main | holds | 308 | yes | main |
| R_Revocation | check | main | holds | 106 | yes | main |
| R_ReissueOutcome | check | small | holds | 2140 | yes | timing |
| WalkExpiryRedundant | check | small | holds | 309 | yes | rerun |
| F2_OpsNeverGrowWithinGeneration | check | small | holds | 4420 | yes | timing |
| A1_NonDelegationChangesOnlyByObjectOwner | check | small | holds | 196 | yes | main |
| A2_DelegationOnlyByParentHolder | check | small | holds | 178 | yes | main |
| A3_RevocationOnlyByObjectOwner | check | small | holds | 66 | yes | main |
| A4_NoUnattributedChange | check | small | holds | 193 | yes | main |
| R1_RootTokensMatchPolicyRoles | check | small | holds | 64 | yes | rerun |
| R2_DelegatedTokensMatchPolicyRoles | check | main | counterexample | 8 | yes | main |

Source `timing` = `results_final/timing/`: a clean re-timing (`suites/timing.json`, run under `caffeinate` on mains power, with no system sleep during the run) of the two checks whose earlier recorded times included laptop sleep. Their earlier verdicts were the same. Every other time listed is shorter than the shortest sleep observed during the runs, so it cannot include sleep.

### Scope scaling (`results_final/scaling/`, seconds; 30-min limit per cell)
| Property | 2 slots / 5 steps | 2 slots / 7 steps | 3 slots / 5 steps | 3 slots / 7 steps | 4 slots / 5 steps | 4 slots / 7 steps |
|---|---|---|---|---|---|---|
| P1_TokenUniqueness | holds (8) | holds (13) | holds (11) | holds (20) | holds (17) | holds (29) |
| P3_AuthCorrectness | holds (13) | holds (12) | holds (26) | holds (49) | holds (620) | holds (288) |
| R_Revocation | holds (8) | holds (7) | holds (10) | holds (18) | holds (83) | holds (97) |
| R_ReissueOutcome | holds (112) | holds (1763) | timeout >30 min | timeout >30 min | timeout >30 min | timeout >30 min |
| P2_EvaluatedChain | holds (38) | holds (318) | holds (880) | timeout >30 min | timeout >30 min | timeout >30 min |
| A4_NoUnattributedChange | holds (35) | holds (86) | holds (234) | holds (768) | holds (824) | timeout >30 min |

No cell produced a counterexample. Timeouts mark where bounded analysis stops scaling on this machine. These runs were partly on battery power, where each solver got about half a CPU core.

### Mutation testing (`results_final/mutation/summary.txt`, small scope)
| Mutant | Result |
|---|---|
| M01_no_single_slot: Remove the one-slot-per-(pair, policy) fact (Assumption as:slot) | Killed |
| M02_reissue_may_widen: Drop FIX 2: re-issue in place may widen ops | Killed |
| M03_delegate_ops_unbounded: Delegation: drop ops' subset of p.ops | Killed |
| M04_delegate_outlives_parent: Delegation: drop t'_exp <= p.t_exp | Killed |
| M05_delegate_depth_not_reduced: Delegation: child depth = parent depth (no decrement) | Killed |
| M06_walk_ignores_ancestor_ops: Ancestor walk: drop 'op in a.tops' | Killed |
| M07_walk_ignores_revocation: Ancestor walk: drop 'a not in Rev' | Killed |
| M08_walk_ignores_generation: Ancestor walk: drop the generation match | Killed |
| M09_walk_ignores_expiry: Ancestor walk: drop the ancestor expiry check (expected equivalent) | Survived |
| M10_fresh_issue_keeps_generation: Fresh issue does not bump the generation counter | Killed |
| M11_auth_uses_eq_as_written: Undo FIX 1: authFixed without the ancestor walk | Killed |
| M12_issue_without_owner_check: issueGrant: drop the caller = own(n_j) guard | Killed |
| M13_revoke_without_owner_check: revokeGrant: drop the caller = own(n_j) guard | Killed |
| M14_delegate_without_holder_check: delegateGrant: drop the caller = holder guard | Killed |
| M15_issue_without_role_match: issueGrant: drop the role-match guard | Killed |

14 of 15 mutants are killed. M09 is an equivalent mutant: `WalkExpiryRedundant` holds, i.e. the ancestor-expiry condition never changes the walk's verdict for a valid token, because a child never outlives its parent.

### Findings
| # | Finding | Evidence | Status |
|---|---|---|---|
| A | Property 2 over stored state fails: a parent can be narrowed or lowered in place after delegation | `results/counterexample_cmd_3.txt`; `P2_StoredState` above | Restate Property 2 both at derivation time (a) and over the evaluated chain (b); both hold |
| B | Assumption asm:issue lets a delegated child be widened beyond its parent | `results/counterexample_cmd_4.txt` | Fix 2 (narrow-only); `F2_OpsNeverGrowWithinGeneration` holds; mutant M02 killed |
| C | Eq. (eq:auth) as written lacks the ancestor walk; Property 3 and Remark rem:revoke fail | `results/counterexample_cmd_5.txt`, `results/counterexample_cmd_7.txt` | Fix 1; P3 and R_Revocation hold; mutant M11 killed |
| D | Delegation may transfer a token to a node whose role differs from the policy's role | `results_final/main/R2_DelegatedTokensMatchPolicyRoles/trace.txt` | **Author decision: intended behaviour** (delegation may cross roles). The model matches the deployed contract, whose `_delegateGrantCore` has no role check. To be stated explicitly in §II. Root tokens do match their policy's roles (R1 holds) |

**Other observations:**
- **Delegation cycles:** §II allows them. The generation check denies both tokens involved (see the 5-step re-issue trace).
- **Ancestor-expiry condition:** redundant in the walk (M09).

### Wording for the manuscript
- Use "no counterexample exists for any configuration within scope …", with the scope stated, followed by "this is not a proof for all sizes (small-scope hypothesis)".
- Never "proved" or "verified" without the bound.
- The analysis covers the §II model, not `NodeRegistry.sol` or the daemon; the model–contract correspondence remains assumed.
