"""r2-c05: same-hardware, same-workload baselines requested by Reviewer 2 (C5):
  (1) an in-process, centralized policy decision point;
  (2) a signed capability checked against an in-memory revocation list.

Both run in-process (no blockchain, no HTTP, no network) on this machine,
timed at the same function-call boundary BlockCap's own single-machine
methodology uses (time.perf_counter() around the decision call only).
Uses the project's own signing library (eth_keys) for baseline (2), for a
like-for-like cryptographic primitive with BlockCap's own signatures.
"""
import json
import os
import platform
import statistics
import subprocess
import time

from eth_keys import keys
from eth_utils import keccak

N = 1000


def percentile(sorted_vals, p):
    k = (len(sorted_vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def summarize(samples_s):
    s = sorted(samples_s)
    med = statistics.median(s)
    p25 = percentile(s, 0.25)
    p75 = percentile(s, 0.75)
    return {
        "n": len(s),
        "median_ms": round(med * 1000, 4),
        "p25_ms": round(p25 * 1000, 4),
        "p75_ms": round(p75 * 1000, 4),
    }


# ---------------------------------------------------------------------------
# Baseline 1: in-process, centralized policy decision point.
# A single in-memory table is both the "policy" and "grant" store -- the
# purely centralized design BlockCap's own abstract contrasts itself with.
# Decision = registered(subject) AND registered(object) AND grant exists AND
# not revoked AND not expired AND op allowed. No serialization, no I/O.
# ---------------------------------------------------------------------------
registered_nodes = {"subjectA", "objectB"}
now = time.time()
grants = {
    ("subjectA", "objectB", "READ"): {"revoked": False, "exp": now + 3600, "ops": {"READ"}},
}


def central_decision(from_id, to_id, op):
    if from_id not in registered_nodes or to_id not in registered_nodes:
        return False
    g = grants.get((from_id, to_id, op))
    if g is None:
        return False
    if g["revoked"]:
        return False
    if time.time() > g["exp"]:
        return False
    if op not in g["ops"]:
        return False
    return True


baseline1_samples = []
for _ in range(N):
    t0 = time.perf_counter()
    ok = central_decision("subjectA", "objectB", "READ")
    t1 = time.perf_counter()
    assert ok
    baseline1_samples.append(t1 - t0)


# ---------------------------------------------------------------------------
# Baseline 2: signed capability checked against an in-memory revocation list.
# The capability is a real ECDSA-signed token (same eth_keys primitive
# BlockCap's own request-proof signing uses); verification recomputes the
# digest, recovers/checks the signature, and checks a revocation set -- no
# blockchain, no shared ledger, purely local state.
# ---------------------------------------------------------------------------
priv = keys.PrivateKey(bytes.fromhex("11" * 32))
pub = priv.public_key

cap_message = {
    "token_id": "cap-0001",
    "subject": "subjectA",
    "object": "objectB",
    "op": "READ",
    "exp": now + 3600,
}
cap_json = json.dumps(cap_message, sort_keys=True)
cap_digest = keccak(text=cap_json)
cap_signature = priv.sign_msg_hash(cap_digest)

revocation_list = {"cap-0099", "cap-0100"}  # unrelated revoked ids; cap-0001 is live


def verify_signed_capability(message_dict, signature, signer_pubkey, revoked_ids):
    message_json = json.dumps(message_dict, sort_keys=True)
    digest = keccak(text=message_json)
    if not signature.verify_msg_hash(digest, signer_pubkey):
        return False
    if message_dict["token_id"] in revoked_ids:
        return False
    if time.time() > message_dict["exp"]:
        return False
    return True


baseline2_samples = []
for _ in range(N):
    t0 = time.perf_counter()
    ok = verify_signed_capability(cap_message, cap_signature, pub, revocation_list)
    t1 = time.perf_counter()
    assert ok
    baseline2_samples.append(t1 - t0)


def git_commit():
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return "unknown"


result = {
    "machine": {
        "cpu_brand": subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
        ).stdout.strip(),
        "platform": platform.platform(),
        "python": platform.python_version(),
    },
    "note_on_hardware": (
        "Run on the machine this revision session executes all single-machine "
        "work on. Its CPU identifies as 'Apple M1 Max'; Table II in the "
        "manuscript describes the single-machine tier as 'Apple MacBook Pro "
        "(M1)' (8-core, unspecified variant). This baseline does not "
        "independently confirm those two descriptions refer to the same "
        "physical unit -- report this discrepancy rather than assume "
        "equivalence."
    ),
    "n": N,
    "git_commit": git_commit(),
    "baseline_in_process_policy_decision": summarize(baseline1_samples),
    "baseline_signed_capability_revocation_list": summarize(baseline2_samples),
    "comparison_note": (
        "For reference, BlockCap's own checkGrant (on-chain read via web3.py, "
        "co-located Besu node, same call-boundary methodology) reports a "
        "published median of 6.5 ms (IQR 5.7-7.1 ms, n=375; see main.tex, "
        "Section VI-A)."
    ),
}

out_path = "/private/tmp/claude-501/-Users-khannmohsin-VSCode-Projects-BlockCap/scratchpad/r2_c05_baseline_results.json"
with open(out_path, "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
