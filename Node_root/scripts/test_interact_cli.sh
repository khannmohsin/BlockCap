#!/usr/bin/env bash
# scripts/test_interact_cli.sh
#
# Self-checking test runner for interact.js (multisig OFF)
# Runs positive & negative cases for: node registration, policy lifecycle,
# non-delegable grants, delegable grants, delegation chain, dynamic policy effects.

set -euo pipefail

# -------- Helpers --------
PASS=0
FAIL=0

banner () { printf "\n========== %s ==========\n" "$*"; }
ok     () { echo "✅  $*"; }
bad    () { echo "❌  $*" >&2; }
incpass() { PASS=$((PASS+1)); }
incfail() { FAIL=$((FAIL+1)); }

# run command that MUST succeed
run_ok () {
  local msg="$1"; shift
  echo "\n$ $*"
  if "$@"; then ok "$msg"; incpass; else bad "$msg"; incfail; fi
}

# run command that MUST fail (revert)
run_fail () {
  local msg="$1"; shift
  echo "\n$ $*"
  if "$@" 2>/dev/null; then
    bad "$msg (unexpected success)"; incfail
  else
    ok "$msg (reverted as expected)"; incpass
  fi
}

# run and assert stdout equals exactly
run_eq () {
  local expect="$1"; shift
  local msg="$1"; shift
  echo "\n$ $*"
  local out
  if ! out=$("$@" 2>&1); then
    bad "$msg (command error)"; echo "$out"; incfail; return
  fi
  if [[ "$out" == "$expect" ]]; then
    ok "$msg"; incpass
  else
    bad "$msg (got: $out ; expected: $expect)"; incfail
  fi
}
# --- time helpers (safe expiries) ---
ts_now()  { node -e "console.log(Math.floor(Date.now()/1000))"; }
ts_plus() { node -e "console.log(Math.floor(Date.now()/1000)+($1|0))"; }

# -------- Environment & Vars --------
banner "Environment"

# Show CLI info
node interact.js help || { echo "Run from repo root with interact.js present."; exit 1; }

FROM=$(node -e "console.log(require('./prefunded_keys.json').prefunded_accounts[0].address)")
echo "CLI sender (FROM): $FROM"

# Unique suffix to avoid collisions
TS=$(node -e "console.log(Date.now())")
EXP600=$(node -e "console.log(Math.floor(Date.now()/1000)+600)")
EXP450=$(node -e "console.log(Math.floor(Date.now()/1000)+450)")

FOG_SIG="fog_${TS}"
EDGEA_SIG="edgeA_${TS}"
EDGEB_SIG="edgeB_${TS}"
EDGEC_SIG="edgeC_${TS}"

# If you are on a clean chain, these IDs will be created in this run:
POLICY_EDGE_FOG_RW_ID=1    # Edge->Fog READ,REMOVE (created in section 2A)
POLICY_EDGE_FOG_RONLY_ID=2 # Edge->Fog READ only   (created in section 3B)
POLICY_EDGE_FOG_RONLY2_ID=3 # fresh READ only (for multi-hop)

# -------- 0) Basic checks --------
banner "0) Basic checks"
run_eq "true"  "checkIfDeployed returns code" node interact.js checkIfDeployed

# -------- 1) Node registration --------
banner "1) Node registration & lookups"

run_ok "Register Fog"  node interact.js registerNode FG-1 Foggy Fog pubFog "$FROM" rpcFog Cloud "$FOG_SIG"
run_ok "Register EdgeA" node interact.js registerNode ED-A EdgeA Edge pubEdgeA "$FROM" rpcEdgeA Cloud "$EDGEA_SIG"
run_ok "Register EdgeB" node interact.js registerNode ED-B EdgeB Edge pubEdgeB "$FROM" rpcEdgeB Cloud "$EDGEB_SIG"

run_eq "true"  "Fog is registered" node interact.js isNodeRegistered "$FOG_SIG"
run_eq "false" "Unknown sig not registered" node interact.js isNodeRegistered nope

run_ok "Lookup Fog by signature" node interact.js getNodeBySig "$FOG_SIG"
run_ok "Lookup Fog by address"   node interact.js getNodeByAddr "$FROM"

run_eq "true"  "Fog is validator" node interact.js isValidator "$FOG_SIG"
run_eq "false" "EdgeA not validator" node interact.js isValidator "$EDGEA_SIG"

run_ok "Propose validator (event tx)" node interact.js proposeValidator "$FROM"

# Negative registration cases
run_fail "ZeroAddr rejected" \
  node interact.js registerNode X Bad Fog pub "0x0000000000000000000000000000000000000000" rpc Cloud "bad_$TS"

run_fail "Invalid node type rejected" \
  node interact.js registerNode X Bad INVALID pub "$FROM" rpc Cloud "bad2_$TS"

run_fail "Duplicate signature rejected" \
  node interact.js registerNode FG-2 Fog2 Fog pub2 "$FROM" rpc2 Cloud "$FOG_SIG"

run_fail "Unknown signature lookup reverts" \
  node interact.js getNodeBySig unknownSig

run_fail "Unknown address lookup reverts" \
  node interact.js getNodeByAddr 0x000000000000000000000000000000000000dEaD

# -------- 2) Policy lifecycle (multisig OFF) --------
banner "2) Policy lifecycle (create/update/deprecate)"

# 2A create Edge->Fog READ,REMOVE as policyId=1
run_ok "Create Edge->Fog READ,REMOVE" node interact.js createPolicy Edge Fog READ,REMOVE

run_ok "Inspect policy #1" node interact.js getPolicy $POLICY_EDGE_FOG_RW_ID

# 2B update to READ only
run_ok "Update policy #1 to READ only" node interact.js updatePolicy $POLICY_EDGE_FOG_RW_ID READ
run_ok "Inspect policy #1 after update" node interact.js getPolicy $POLICY_EDGE_FOG_RW_ID

# 2C deprecate
run_ok "Deprecate policy #1" node interact.js deprecatePolicy $POLICY_EDGE_FOG_RW_ID
run_ok "Inspect policy #1 after deprecate" node interact.js getPolicy $POLICY_EDGE_FOG_RW_ID

# Negative policy cases
run_fail "Create with Unknown role rejected" node interact.js createPolicy Unknown Fog READ
run_fail "Create with ops=0 rejected"        node interact.js createPolicy Edge Fog 0
run_fail "Update deprecated policy rejected" node interact.js updatePolicy $POLICY_EDGE_FOG_RW_ID READ,REMOVE

# -------- 3) Grants (non-delegable) --------
banner "3) Grants (non‑delegable) + dynamic policy check"

# 3A Create fresh READ,REMOVE policy as #2
run_ok "Create policy #2 Edge->Fog READ,REMOVE" node interact.js createPolicy Edge Fog READ,REMOVE

# 3B Issue grant (READ subset) A->Fog under policy #2
run_ok "Issue grant READ to EdgeA->Fog" node interact.js issueGrant "$EDGEA_SIG" "$FOG_SIG" $POLICY_EDGE_FOG_RONLY_ID READ "$EXP600"

run_eq "true"  "checkGrant READ true"   node interact.js checkGrant "$EDGEA_SIG" "$FOG_SIG" READ
run_eq "false" "checkGrant REMOVE false" node interact.js checkGrant "$EDGEA_SIG" "$FOG_SIG" REMOVE

run_ok "getGrant shows active" node interact.js getGrant "$EDGEA_SIG" "$FOG_SIG"

# 3C Update policy #2 to READ only (tighten)
run_ok "Tighten policy #2 to READ only" node interact.js updatePolicy $POLICY_EDGE_FOG_RONLY_ID READ
run_eq "false" "REMOVE now false due to tightened policy" node interact.js checkGrant "$EDGEA_SIG" "$FOG_SIG" REMOVE
run_eq "true"  "READ remains true"                       node interact.js checkGrant "$EDGEA_SIG" "$FOG_SIG" READ

# 3D Revoke + expiry check
run_ok "Revoke grant EdgeA->Fog" node interact.js revokeGrant "$EDGEA_SIG" "$FOG_SIG"
run_eq "false" "READ after revoke is false" node interact.js checkGrant "$EDGEA_SIG" "$FOG_SIG" READ
run_eq "true"  "isGrantExpired true after revoke" node interact.js isGrantExpired "$EDGEA_SIG" "$FOG_SIG"

# Reissue a short grant then mine a block via tx and re-check
EXP_SHORT=$(node -e "console.log(Math.floor(Date.now()/1000)+8)")
run_ok "Reissue short grant" node interact.js issueGrant "$EDGEA_SIG" "$FOG_SIG" $POLICY_EDGE_FOG_RONLY_ID READ "$EXP_SHORT"
sleep 9
# mine a block to update timestamp (use proposeValidator for a cheap tx)
run_ok "Mine a block to advance time" node interact.js proposeValidator "$FROM"
run_eq "true" "Grant shows expired" node interact.js isGrantExpired "$EDGEA_SIG" "$FOG_SIG"

# Negative grant case: double-issue on active grant
run_ok "Issue long grant again" node interact.js issueGrant "$EDGEA_SIG" "$FOG_SIG" $POLICY_EDGE_FOG_RONLY_ID READ "$EXP600"
run_fail "Re-issuing while active rejected" \
  node interact.js issueGrant "$EDGEA_SIG" "$FOG_SIG" $POLICY_EDGE_FOG_RONLY_ID READ "$EXP600"
# clean up
run_ok "Revoke long grant" node interact.js revokeGrant "$EDGEA_SIG" "$FOG_SIG"

# -------- 4) Delegation (delegable root -> child) --------
banner "4) Delegation (delegable root -> child) and dynamic policy"

# Root delegable: EdgeA->Fog, READ,REMOVE, depth=2 under policy #2
run_ok "Delegable root grant (READ only to match policy #2)" \
  node interact.js issueGrantDelegable "$EDGEA_SIG" "$FOG_SIG" $POLICY_EDGE_FOG_RONLY_ID READ "$EXP600" true 2

# Delegate to EdgeB (reduced rights READ, earlier expiry)
run_ok "Delegate A->B (READ only)" \
  node interact.js delegateGrant "$EDGEA_SIG" "$FOG_SIG" "$EDGEB_SIG" READ "$EXP450"

run_eq "true"  "B has READ"   node interact.js checkGrant "$EDGEB_SIG" "$FOG_SIG" READ
run_eq "false" "B lacks REMOVE" node interact.js checkGrant "$EDGEB_SIG" "$FOG_SIG" REMOVE

run_ok "getGrantEx shows flags" node interact.js getGrantEx "$EDGEB_SIG" "$FOG_SIG"

# Tighten policy to READ only -> REMOVE should fail for delegated child
run_ok "Tighten policy #2 to READ only" node interact.js updatePolicy $POLICY_EDGE_FOG_RONLY_ID READ
run_eq "false" "B REMOVE false after tighten" node interact.js checkGrant "$EDGEB_SIG" "$FOG_SIG" REMOVE
run_eq "true"  "B READ still true"           node interact.js checkGrant "$EDGEB_SIG" "$FOG_SIG" READ

# Deprecate policy -> checks fail
run_ok "Deprecate policy #2" node interact.js deprecatePolicy $POLICY_EDGE_FOG_RONLY_ID
run_eq "false" "B READ false after deprecate" node interact.js checkGrant "$EDGEB_SIG" "$FOG_SIG" READ
run_ok "Revoke root grant A->Fog from section 4" node interact.js revokeGrant "$EDGEA_SIG" "$FOG_SIG"
run_eq "true" "Section-4 root grant is expired/invalidated" node interact.js isGrantExpired "$EDGEA_SIG" "$FOG_SIG"
# Make sure no leftover child grant blocks the new multi-hop section
run_ok "Revoke delegated child grant B->Fog from section 4" node interact.js revokeGrant "$EDGEB_SIG" "$FOG_SIG"
run_eq "true" "Child grant B->Fog is expired/invalidated" node interact.js isGrantExpired "$EDGEB_SIG" "$FOG_SIG"

# -------- 5) Multi-hop (A->B->C) with depth consumption --------
banner "5) Multi-hop delegation with depth consumption"

# New fresh policy #3 (READ)
run_ok "Create policy #3 Edge->Fog READ" node interact.js createPolicy Edge Fog READ

# Register EdgeC
run_ok "Register EdgeC" node interact.js registerNode ED-C EdgeC Edge pubEdgeC "$FROM" rpcEdgeC Cloud "$EDGEC_SIG"

# Root: A->Fog (READ, depth=2)
run_ok "Root depth=2" \
  node interact.js issueGrantDelegable "$EDGEA_SIG" "$FOG_SIG" $POLICY_EDGE_FOG_RONLY2_ID READ "$EXP600" true 2

# A->B (depth 2->1)
run_ok "A->B" node interact.js delegateGrant "$EDGEA_SIG" "$FOG_SIG" "$EDGEB_SIG" READ "$EXP600"

# B->C (depth 1->0)
run_ok "B->C" node interact.js delegateGrant "$EDGEB_SIG" "$FOG_SIG" "$EDGEC_SIG" READ "$EXP450"

run_eq "true"  "C has READ" node interact.js checkGrant "$EDGEC_SIG" "$FOG_SIG" READ
run_eq "false" "C lacks REMOVE" node interact.js checkGrant "$EDGEC_SIG" "$FOG_SIG" REMOVE

# Depth exhausted -> cannot delegate further
run_fail "C cannot delegate further (depth=0)" \
  node interact.js delegateGrant "$EDGEC_SIG" "$FOG_SIG" "$EDGEA_SIG" READ "$EXP450"

# --- fresh actors for Sections 6–7 to avoid collisions with earlier grants ---
OPS_FOG_SIG="fog_ops_${TS}"
OPS_EDGEA_SIG="edgeA_ops_${TS}"
OPS_EDGEB_SIG="edgeB_ops_${TS}"
OPS_EDGEC_SIG="edgeC_ops_${TS}"

run_ok "Register Fog (ops suite)"   node interact.js registerNode FG-OPS FogOps Fog pubFogOps "$FROM" rpcFogOps Cloud "$OPS_FOG_SIG"
run_ok "Register EdgeA (ops suite)" node interact.js registerNode ED-A-OPS EdgeAOps Edge pubEdgeAOps "$FROM" rpcEdgeAOps Cloud "$OPS_EDGEA_SIG"
run_ok "Register EdgeB (ops suite)" node interact.js registerNode ED-B-OPS EdgeBOps Edge pubEdgeBOps "$FROM" rpcEdgeBOps Cloud "$OPS_EDGEB_SIG"
run_ok "Register EdgeC (ops suite)" node interact.js registerNode ED-C-OPS EdgeCOps Edge pubEdgeCOps "$FROM" rpcEdgeCOps Cloud "$OPS_EDGEC_SIG"

# -------- 6) Ops / mask / role edge cases --------
banner "6) Ops / mask / role edge cases"

# Fresh policy #4: Edge->Fog with READ|WRITE|UPDATE|REMOVE
run_ok "Create policy #4 Edge->Fog READ,WRITE,UPDATE,REMOVE" \
  node interact.js createPolicy Edge Fog READ,WRITE,UPDATE,REMOVE

# Issue with numeric mask (5 == READ|UPDATE) to confirm numeric path
run_ok "Issue A->Fog with numeric mask 5 (READ|UPDATE)" \
  node interact.js issueGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 4 5 "$EXP600"

run_eq "true"  "A->Fog has READ (from mask 5)"   node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" READ
run_eq "true"  "A->Fog has UPDATE (from mask 5)" node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" UPDATE
run_eq "false" "A->Fog lacks WRITE (not in mask 5)"  node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" WRITE
run_eq "false" "A->Fog lacks REMOVE (not in mask 5)" node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" REMOVE

# Update policy #4 to only WRITE|REMOVE. READ & UPDATE should now fail dynamically.
run_ok "Tighten policy #4 to WRITE,REMOVE only" \
  node interact.js updatePolicy 4 WRITE,REMOVE

run_eq "false" "A->Fog READ false after tighten"    node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" READ
run_eq "false" "A->Fog UPDATE false after tighten"  node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" UPDATE
run_eq "false" "A->Fog WRITE still false (not granted)"  node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" WRITE
run_eq "false" "A->Fog REMOVE still false (not granted)" node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" REMOVE

# Revoke cleanup for this grant
run_ok "Revoke A->Fog (policy #4)" node interact.js revokeGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG"

# Unknown op keyword -> interact.js parseOps should reject
run_fail "Unknown op keyword rejected at CLI" \
  node interact.js issueGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 4 FOO "$EXP600"

# Mixed delimiter/whitespace robustness at CLI:
run_ok "Create policy #5 with CSV and spaces" node interact.js createPolicy Edge Fog "READ,  REMOVE"
# Issue grant with pipe delimiter
run_ok "Issue A->Fog under policy #5 with pipe delimiter ops" \
  node interact.js issueGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 5 "READ|REMOVE" "$EXP600"
run_eq "true"  "check READ true (policy #5)"   node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" READ
run_eq "true"  "check REMOVE true (policy #5)" node interact.js checkGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" REMOVE

# Mismatched roles / direction (Fog->Edge under Edge->Fog policy should revert)
run_fail "Issuing grant with reversed direction (Fog->Edge) rejected" \
  node interact.js issueGrant "$OPS_FOG_SIG" "$OPS_EDGEA_SIG" 5 READ "$EXP600"

# Non‑registered parties (use a random signature that is not registered)
RAND_SIG="rand_${TS}"
run_fail "Issue from unregistered fromSig rejected" \
  node interact.js issueGrant "$RAND_SIG" "$OPS_FOG_SIG" 5 READ "$EXP600"
run_fail "Issue to unregistered toSig rejected" \
  node interact.js issueGrant "$OPS_EDGEA_SIG" "$RAND_SIG" 5 READ "$EXP600"

# Invalid policy id
run_fail "Issue with unknown policy id rejected" \
  node interact.js issueGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 999 READ "$EXP600"

# ops=0 should be rejected on issue
run_fail "Issue with ops=0 rejected" \
  node interact.js issueGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 5 0 "$EXP600"

# Expiry in the past should be rejected (use now-5)
EXP_PAST=$(node -e "console.log(Math.floor(Date.now()/1000)-5)")
run_fail "Issue with past expiry rejected" \
  node interact.js issueGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 5 READ "$EXP_PAST"

# Double revoke should fail (depends on contract behavior; expect revert)
run_ok   "Revoke A->Fog once (policy #5)" node interact.js revokeGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG"
run_fail "Revoke A->Fog again rejected"   node interact.js revokeGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG"

# -------- 7) Delegation constraints & edge cases --------
banner "7) Delegation constraints & edge cases"

# Fresh policy #6: Edge->Fog READ,REMOVE (to test delegationAllowed flag)
run_ok "Create policy #6 Edge->Fog READ,REMOVE" node interact.js createPolicy Edge Fog READ,REMOVE

# (A) Non‑delegable root blocks delegation
ROOT_EXP=$(ts_plus 1200)   # 20 min
run_ok "Issue delegable=false root A->Fog (READ only, depth=2)" \
  node interact.js issueGrantDelegable "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 6 READ "$ROOT_EXP" false 2

run_fail "Delegate A->B blocked when delegationAllowed=false" \
  node interact.js delegateGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" "$OPS_EDGEB_SIG" READ "$(ts_plus 900)"

run_ok "Revoke non‑delegable root A->Fog (policy #6)" node interact.js revokeGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG"

# (B) Delegable root, enforce subset + expiry rules
ROOT_EXP=$(ts_plus 1800)   # 30 min, fresh timestamp to avoid drift
run_ok "Issue delegable root A->Fog (READ only, depth=2) under policy #6" \
  node interact.js issueGrantDelegable "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 6 READ "$ROOT_EXP" true 2

run_fail "Delegate A->B with ops not subset (REMOVE) rejected" \
  node interact.js delegateGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" "$OPS_EDGEB_SIG" REMOVE "$(ts_plus 1200)"

# Beyond parent should fail
EXP_TOO_LONG=$(ts_plus 4000)
run_fail "Delegate A->B expiry beyond parent rejected" \
  node interact.js delegateGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" "$OPS_EDGEB_SIG" READ "$EXP_TOO_LONG"

# Valid A->B with explicit, earlier expiry
B_EXP=$(ts_plus 1200)  # < ROOT_EXP
run_ok "Delegate A->B valid (READ, within expiry)" \
  node interact.js delegateGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" "$OPS_EDGEB_SIG" READ "$B_EXP"
run_eq "true" "B can READ" node interact.js checkGrant "$OPS_EDGEB_SIG" "$OPS_FOG_SIG" READ

# C must be strictly shorter than B, and still in the future
C_EXP=$(ts_plus 600)    # < B_EXP
run_fail "B->C with REMOVE (not subset) rejected" \
  node interact.js delegateGrant "$OPS_EDGEB_SIG" "$OPS_FOG_SIG" "$OPS_EDGEC_SIG" REMOVE "$C_EXP"

# Same/longer than B should fail
run_fail "B->C with same/longer expiry rejected" \
  node interact.js delegateGrant "$OPS_EDGEB_SIG" "$OPS_FOG_SIG" "$OPS_EDGEC_SIG" READ "$B_EXP"

# Valid B->C (shorter expiry)
run_ok "B->C valid (READ, shorter expiry)" \
  node interact.js delegateGrant "$OPS_EDGEB_SIG" "$OPS_FOG_SIG" "$OPS_EDGEC_SIG" READ "$C_EXP"
run_eq "true" "C can READ (delegated)" node interact.js checkGrant "$OPS_EDGEC_SIG" "$OPS_FOG_SIG" READ

# Depth exhausted -> C cannot delegate further
run_fail "C->A when depth exhausted rejected" \
  node interact.js delegateGrant "$OPS_EDGEC_SIG" "$OPS_FOG_SIG" "$OPS_EDGEA_SIG" READ "$(ts_plus 300)"

# (C) Root revoke does NOT cascade (your chosen semantics)
run_ok "Revoke A->Fog (root) — children remain until explicitly revoked" node interact.js revokeGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG"
run_eq "true"  "B READ remains true after root revoke (no cascade)" node interact.js checkGrant "$OPS_EDGEB_SIG" "$OPS_FOG_SIG" READ
run_eq "true"  "C READ remains true after root revoke (no cascade)"  node interact.js checkGrant "$OPS_EDGEC_SIG" "$OPS_FOG_SIG" READ

# Explicitly revoke children (C first is ok because C exists now)
run_ok "Revoke C->Fog after root revoke" node interact.js revokeGrant "$OPS_EDGEC_SIG" "$OPS_FOG_SIG"
run_ok "Revoke B->Fog after root revoke" node interact.js revokeGrant "$OPS_EDGEB_SIG" "$OPS_FOG_SIG"
run_eq "false" "B READ false after child revoke" node interact.js checkGrant "$OPS_EDGEB_SIG" "$OPS_FOG_SIG" READ
run_eq "false" "C READ false after child revoke" node interact.js checkGrant "$OPS_EDGEC_SIG" "$OPS_FOG_SIG" READ

# Unknown policy id rejected
run_fail "Issue root with unknown policy id rejected" \
  node interact.js issueGrantDelegable "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 999 READ "$(ts_plus 900)" true 2

# ops=0 rejected at delegate call
run_ok "Re‑issue valid root A->Fog (policy #6, READ, depth=1)" \
  node interact.js issueGrantDelegable "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" 6 READ "$(ts_plus 900)" true 1
run_fail "Delegate with ops=0 rejected" \
  node interact.js delegateGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG" "$OPS_EDGEB_SIG" 0 "$(ts_plus 600)"
run_ok "Revoke last root (policy #6)" node interact.js revokeGrant "$OPS_EDGEA_SIG" "$OPS_FOG_SIG"

# -------- Summary --------
banner "DONE  |  PASS: $PASS  FAIL: $FAIL"
test $FAIL -eq 0