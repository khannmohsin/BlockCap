#!/usr/bin/env bash
# scripts/test_interact_msig.sh
#
# Multisignature tests for interact.js
# Safe to run on a fresh chain alongside your other tests.

set -euo pipefail

# -------- Helpers --------
PASS=0; FAIL=0
banner  () { printf "\n========== %s ==========\n" "$*"; }
ok      () { echo "✅  $*"; }
bad     () { echo "❌  $*" >&2; }
incpass () { PASS=$((PASS+1)); }
incfail () { FAIL=$((FAIL+1)); }

# Run a command that MUST succeed (supports inline env like FROM_IDX=1 ...)
run_ok () {
  local msg="$1"; shift
  local cmd="$*"
  echo -e "\n$ $cmd"
  if bash -lc "$cmd"; then ok "$msg"; incpass; else bad "$msg"; incfail; fi
}

# Run a command that MUST fail (revert)
run_fail () {
  local msg="$1"; shift
  local cmd="$*"
  echo -e "\n$ $cmd"
  if bash -lc "$cmd" 2>/dev/null; then
    bad "$msg (unexpected success)"; incfail
  else
    ok "$msg (reverted as expected)"; incpass
  fi
}

# Run and assert stdout equals exactly
run_eq () {
  local expect="$1"; shift
  local msg="$1"; shift
  local cmd="$*"
  echo -e "\n$ $cmd"
  local out
  if ! out=$(bash -lc "$cmd" 2>&1); then
    bad "$msg (command error)"; echo "$out"; incfail; return
  fi
  if [[ "$out" == "$expect" ]]; then ok "$msg"; incpass
  else bad "$msg (got: $out ; expected: $expect)"; incfail
  fi
}

# Time helper: now + N seconds (epoch seconds)
ts_plus () { node -e "console.log(Math.floor(Date.now()/1000)+(${1:-0}))"; }

# Random 32‑byte schema salt (hex string 0x...)
rand_schema () { node -e "console.log('0x'+require('crypto').randomBytes(32).toString('hex'))"; }

# -------- Env --------
banner "Environment"
node interact.js help >/dev/null || { echo "Run from repo root."; exit 1; }

ADDR0=$(node -e "console.log(require('./prefunded_keys.json').prefunded_accounts[0].address)")
ADDR1=$(node -e "console.log(require('./prefunded_keys.json').prefunded_accounts[1].address)")
ADDR2=$(node -e "console.log(require('./prefunded_keys.json').prefunded_accounts[2].address)")
echo "Signers:"
echo "  A0 (default) : $ADDR0"
echo "  A1 (approver): $ADDR1"
echo "  A2 (approver): $ADDR2"

TS=$(node -e "console.log(Date.now())")

run_eq "true" "Contract code present" node interact.js checkIfDeployed

# -------- 0) Turn ON multisig & configure --------
banner "0) Enable multisig & configure approvers"

run_ok   "Enable multisig"          node interact.js msigMode true
run_ok   "Add approver A1"         node interact.js msigAdd "$ADDR1"
run_ok   "Add approver A2"         node interact.js msigAdd "$ADDR2"
run_ok   "Set threshold=2"         node interact.js msigThreshold 2
run_ok   "msig info"               node interact.js msigInfo
run_eq   "true"  "A1 is approver"  node interact.js msigIsApprover "$ADDR1"
run_eq   "true"  "A2 is approver"  node interact.js msigIsApprover "$ADDR2"
run_eq   "false" "A0 not approver" node interact.js msigIsApprover "$ADDR0"

# -------- 1) createPolicy must NOT work directly when multisig ON --------
banner "1) Direct createPolicy is blocked"
run_fail "createPolicy (direct) blocked by msig" node interact.js createPolicy Edge Fog READ

# -------- 2) Two-step approval flow creates the policy --------
banner "2) Approval flow (threshold=2)"

# Unique schema for this flow to avoid collisions with later tests
SCHEMA_FIRST=$(rand_schema)

run_ok   "A1 approves Edge->Fog READ" \
  FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_FIRST"

run_fail "A1 duplicate approval rejected" \
  FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_FIRST"

run_fail "Non-approver A0 cannot approve" \
  FROM_IDX=0 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_FIRST"

run_ok   "A2 approves (threshold met -> policy created)" \
  FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_FIRST"

run_ok   "Inspect policy #1" node interact.js getPolicy 1

# -------- 3) Threshold=1 -> single approval creates policy --------
banner "3) Threshold=1 -> single approval creates policy"
run_ok   "Set threshold=1" node interact.js msigThreshold 1

SCHEMA_SINGLE=$(rand_schema)
run_ok   "A1 single-approval creates policy #2 Edge->Fog READ,REMOVE" \
  FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ,REMOVE "$SCHEMA_SINGLE"

run_ok   "Inspect policy #2" node interact.js getPolicy 2
run_fail "Setting threshold > approver count rejected" node interact.js msigThreshold 3

# -------- 4) Remove an approver & verify behavior --------
banner "4) Remove approver and verify"
run_ok   "Remove approver A2" node interact.js msigRemove "$ADDR2"
run_eq   "false" "A2 no longer approver" node interact.js msigIsApprover "$ADDR2"

SCHEMA_ONLYA1=$(rand_schema)
run_ok   "A1 creates policy #3 (threshold=1, one approver left)" \
  FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog UPDATE "$SCHEMA_ONLYA1"

run_ok   "Inspect policy #3" node interact.js getPolicy 3
run_fail "Threshold=2 with only one approver rejected" node interact.js msigThreshold 2

# -------- 5) Turn OFF multisig and ensure direct create works --------
banner "5) Disable multisig and createPolicy directly works"
run_ok   "Disable multisig" node interact.js msigMode false
run_ok   "Direct createPolicy works when msig off" node interact.js createPolicy Edge Fog REMOVE
run_ok   "Inspect first created policy (should be #1 on fresh chain)" node interact.js getPolicy 1

# -------- 6) Worst-cases & hard edges --------
banner "6) Worst-cases & hard edges"

# 6.1 Threshold hygiene
run_fail "Threshold cannot be 0" node interact.js msigThreshold 0
run_ok   "Re-enable msig" node interact.js msigMode true
run_fail "Threshold 2 with 1 approver rejected" node interact.js msigThreshold 2
run_ok   "Add back A2 for more tests" node interact.js msigAdd "$ADDR2"
run_ok   "Set threshold=2 (valid now)" node interact.js msigThreshold 2

# 6.2 Approver set integrity
run_fail "Duplicate msigAdd rejected" node interact.js msigAdd "$ADDR2"
run_fail "Remove non-approver rejected" node interact.js msigRemove "$ADDR0"

# 6.3 Pending approval invalidated by removal (use a UNIQUE schema to avoid payload replay)
SCHEMA_P=$(rand_schema)
run_ok   "A1 approves Proposal P (READ)" FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_P"
run_ok   "Remove A1 while P is pending"  node interact.js msigRemove "$ADDR1"
run_eq   "false" "A1 is not approver anymore" node interact.js msigIsApprover "$ADDR1"
run_fail "A2 approval cannot complete P (threshold unmet)" FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_P"
run_ok   "Re-add A1" node interact.js msigAdd "$ADDR1"
run_ok   "A1 re-approves P" FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_P"
run_ok   "A2 approves P -> policy created" FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_P"
run_ok   "Inspect policy #5 (P)" node interact.js getPolicy 5

# 6.4 Proposal collision / cross-contamination (distinct payloads via SCHEMA_X / SCHEMA_Y)
SCHEMA_X=$(rand_schema)
SCHEMA_Y=$(rand_schema)
run_ok   "Set threshold=2 (explicit)" node interact.js msigThreshold 2
run_ok   "A1 approves X (READ)"  FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_X"
run_ok   "A2 approves Y (WRITE)" FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog WRITE "$SCHEMA_Y"
run_ok   "A2 also approves X (READ) -> creates policy X" FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_X"
run_ok   "Inspect next policy (X)" node interact.js getPolicy 6
run_ok   "A1 approves Y (WRITE) -> creates policy Y" FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog WRITE "$SCHEMA_Y"
run_ok   "Inspect next policy (Y)" node interact.js getPolicy 7

# 6.5 Payload hashing strictness (different schema variants)
SCHEMA_A="0x"$(printf "%064x" 1)
SCHEMA_B="0x"$(printf "%064x" 2)
run_ok   "A1 approve Z with schema A" FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_A"
run_ok   "A2 approve Z with schema B (different) -> no create yet" FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_B"
run_ok   "A2 approve Z with schema A -> creates Z" FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_A"
run_ok   "Inspect next policy (Z)" node interact.js getPolicy 8

# 6.6 Replay protection after creation
run_fail "Duplicate approval for created Z rejected" FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog READ "$SCHEMA_A"

# 6.7 Mode flapping with pending approvals (use UNIQUE schema to avoid collisions)
run_ok   "Threshold=2 (ensure strict)" node interact.js msigThreshold 2
SCHEMA_W=$(rand_schema)
run_ok   "A1 approves W (UPDATE)" FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog UPDATE "$SCHEMA_W"
run_ok   "Turn msig OFF mid-pending" node interact.js msigMode false
run_ok   "Direct create works while msig OFF" node interact.js createPolicy Edge Fog REMOVE
run_ok   "Turn msig back ON" node interact.js msigMode true
if [[ "$(node interact.js msigIsApprover "$ADDR2")" == "true" ]]; then
  ok "A2 already approver"
else
  run_ok "Add A2 back" node interact.js msigAdd "$ADDR2"
fi
run_ok "Set threshold=2 again" node interact.js msigThreshold 2
run_ok   "A2 approves W (fresh epoch, matching schema)" FROM_IDX=2 node interact.js approveCreatePolicy Edge Fog UPDATE "$SCHEMA_W"
# Optional third call—some impls will ignore extra matching approvals; allow success or no-op
run_ok   "Optional: A1 re-approves W to complete under fresh epoch" FROM_IDX=1 node interact.js approveCreatePolicy Edge Fog UPDATE "$SCHEMA_W" || true
run_ok   "Inspect next policy (W)" node interact.js getPolicy 10 || true

# -------- Summary --------
banner "DONE  |  PASS: $PASS  FAIL: $FAIL"
test $FAIL -eq 0