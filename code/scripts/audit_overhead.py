#!/usr/bin/env python3
"""Measure the overhead of the signed, on-chain-anchored audit log.

Two fresh local topologies (1 cloud + 1 fog + 1 edge) are run in sequence,
with the audit log OFF (AUDIT_LOG=0) and then ON (AUDIT_LOG=1). In each, the
edge node requests access to the fog node (the enforcing node); the Edge->Fog
READ policy for the resource is created first through the root's admin route:
one cold request establishes the grant, then N warm requests to the
established state are timed client-side with time.perf_counter around the
HTTP call, as run_all_experiments.timed_request does. Every request carries a
fresh signed request proof.

With logging ON the script additionally:
  - waits for the count-based anchors (AUDIT_ANCHOR_EVERY) to land,
  - reads anchorAuditRoot gas from the fog node's gas_log.jsonl and anchor
    latency from its audit_log.anchors.jsonl,
  - reads auditSeq/auditRoot back from the contract,
  - verifies the log, the anchors, and every receipt the client received.

Results: experiment_results/audit_overhead/<UTC timestamp>/ (summary.json,
samples_off.json, samples_on.json, verify.json). Topologies are stopped at the
end of each phase.
"""
import argparse
import datetime as dt
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "Node_root"))
from node_identity import sign_request_proof  # noqa: E402
import audit_log  # noqa: E402

METHOD, PATH = "GET", "/audit-overhead"
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN") or "audit-overhead-" + os.urandom(8).hex()
EXTRA = {"expiry_secs": 3600, "allow_delegation": False, "delegation_depth": 0, "audit": True}


def start_topology(scenario: str, audit_on: bool, anchor_every: int) -> dict:
    env = os.environ.copy()
    env.update(AUDIT_LOG="1" if audit_on else "0", AUDIT_ANCHOR_EVERY=str(anchor_every),
               AUDIT_ANCHOR_INTERVAL_S="3600", ADMIN_TOKEN=ADMIN_TOKEN)
    cmd = [sys.executable, str(REPO / "scripts" / "run_topology.py"), "--cloud", "1", "--fog", "1",
           "--edge", "1", "--endpoint", "0", "--scenario", scenario, "--runtime-backend", "native"]
    subprocess.run(cmd, check=True, env=env, cwd=REPO)
    return json.loads((REPO / "runtime" / "generated" / scenario / "topology.json").read_text())


def stop_topology(manifest: dict) -> None:
    pids = []
    for n in manifest.get("nodes", []):
        pids += [n.get("api_pid"), n.get("control_pid"), n.get("chain_pid")]
    r = manifest.get("root", {})
    pids += [r.get("service_pid"), r.get("chain_pid")]
    for pid in filter(None, pids):
        try:
            os.killpg(int(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(int(pid), signal.SIGTERM)
            except Exception:
                pass
    time.sleep(3)


_last_nonce = [0]


def body(root_sig, root_key, fog_sig, k):
    # The daemon requires a fresh, non-future millisecond timestamp, unique per
    # request: use wall-clock ms, bumped to stay strictly increasing.
    nonce = max(int(time.time() * 1000), _last_nonce[0] + 1)
    _last_nonce[0] = nonce
    proof = sign_request_proof(root_sig, fog_sig, METHOD, PATH, nonce, root_key, extra_fields=EXTRA)
    return {"from_signature": root_sig, "to_signature": fog_sig, "method": METHOD,
            "resource_path": PATH, **EXTRA, "nonce_ms": nonce, "request_proof": proof}


def run_phase(audit_on: bool, n: int, anchor_every: int, stamp: str) -> dict:
    scenario = f"audit-overhead-{'on' if audit_on else 'off'}-{stamp}"
    m = start_topology(scenario, audit_on, anchor_every)
    try:
        root = m["root"]
        fog = next(n for n in m["nodes"] if n["tier"] == "fog")
        edge = next(n for n in m["nodes"] if n["tier"] == "edge")
        # Requester: the edge node (registered, holds its own key).
        root_sig = edge["payload"]["signature"]
        root_key = str(Path(edge["directory"]) / "data" / "key.priv")
        fog_sig, api = fog["payload"]["signature"], fog["api_url"].rstrip("/")
        pol = requests.post(root["api_url"].rstrip("/") + "/policy/create",
                            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
                            json={"from_role": "Edge", "to_role": "Fog", "ops_csv": "READ",
                                  "ctx_schema": f"api:{METHOD}:{PATH}"}, timeout=120)
        if not pol.ok:
            raise RuntimeError(f"policy create failed: {pol.status_code} {pol.text[:300]}")
        cold = requests.post(api + "/access", json=body(root_sig, root_key, fog_sig, 0), timeout=60)
        if not (cold.ok and cold.json().get("granted")):
            raise RuntimeError(f"cold request not granted: {cold.status_code} {cold.text[:300]}")
        samples, receipts = [], []
        if audit_on and cold.json().get("audit_receipt"):
            receipts.append(cold.json()["audit_receipt"])
        for k in range(1, n + 1):
            b = body(root_sig, root_key, fog_sig, k)
            t0 = time.perf_counter()
            r = requests.post(api + "/access", json=b, timeout=30)
            ms = round((time.perf_counter() - t0) * 1000, 3)
            p = r.json()
            samples.append({"latency_ms": ms, "status": r.status_code, "granted": bool(p.get("granted"))})
            if p.get("audit_receipt"):
                receipts.append(p["audit_receipt"])
        out = {"scenario": scenario, "samples": samples, "receipts": receipts,
               "fog_dir": fog["directory"], "rpc_url": fog["rpc_url"]}
        if audit_on:
            data = Path(fog["directory"]) / "data"
            anchors_path = data / "audit_log.anchors.jsonl"
            want = ((n + 1) // anchor_every) * anchor_every
            deadline = time.time() + 120
            while time.time() < deadline:
                anchors = audit_log.load(anchors_path) if anchors_path.exists() else []
                if anchors and max(a["seq"] for a in anchors) >= want:
                    break
                time.sleep(1)
            entries = audit_log.load(data / "audit_log.jsonl")
            anchors = audit_log.load(anchors_path) if anchors_path.exists() else []
            out["anchors"] = anchors
            out["verify"] = audit_log.verify(entries, anchors, receipts)
            out["onchain"] = read_onchain(fog, anchors)
            out["anchor_gas"] = out["onchain"]["anchor_gas"]
        return out
    finally:
        stop_topology(m)


def read_onchain(fog: dict, anchors: list) -> dict:
    """auditSeq/auditRoot for each address that emitted AuditRootAnchored."""
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(fog["rpc_url"]))
    art = json.loads((Path(fog["directory"]) / "data" / "NodeRegistry.json").read_text())
    addr = art.get("address") or art.get("networks", {}).get(next(iter(art.get("networks", {})), ""), {}).get("address")
    c = w3.eth.contract(address=Web3.to_checksum_address(addr), abi=art["abi"])
    logs = c.events.AuditRootAnchored().get_logs(from_block=0)
    by = {}
    for lg in logs:
        a = lg["args"]["anchoredBy"]
        by[a] = {"seq": int(c.functions.auditSeq(a).call()),
                 "root": "0x" + c.functions.auditRoot(a).call().hex().removeprefix("0x")}
    events = [{"seq": int(l["args"]["seq"]), "root": "0x" + l["args"]["root"].hex().removeprefix("0x")} for l in logs]
    last = max(anchors, key=lambda a: a["seq"]) if anchors else None
    # Gas per anchor, read from the on-chain transaction receipts.
    gas = [int(w3.eth.get_transaction_receipt(a["tx"])["gasUsed"]) for a in anchors if a.get("tx")]
    return {"events": events, "state": by, "anchor_gas": gas,
            "matches_last_local_anchor": bool(last and any(v == {"seq": last["seq"], "root": last["root"]}
                                                           for v in by.values()))}


def stats(xs):
    xs = sorted(xs)
    p95 = xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]
    return {"n": len(xs), "mean": round(statistics.mean(xs), 3), "sd": round(statistics.stdev(xs), 3),
            "median": round(statistics.median(xs), 3), "p95": round(p95, 3)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--anchor-every", type=int, default=50)
    a = ap.parse_args()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = REPO / "experiment_results" / "audit_overhead" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    phases = {}
    for on in (False, True):
        res = run_phase(on, a.n, a.anchor_every, stamp)
        key = "on" if on else "off"
        (out_dir / f"samples_{key}.json").write_text(json.dumps(res["samples"], indent=1))
        phases[key] = res
        print(f"[{key}] done: {len(res['samples'])} warm samples", flush=True)
    summary = {"date_utc": stamp, "n_warm": a.n, "anchor_every": a.anchor_every,
               "besu": subprocess.run(["besu", "--version"], capture_output=True, text=True).stdout.strip(),
               "warm_off": stats([s["latency_ms"] for s in phases["off"]["samples"]]),
               "warm_on": stats([s["latency_ms"] for s in phases["on"]["samples"]]),
               "granted_off": sum(s["granted"] for s in phases["off"]["samples"]),
               "granted_on": sum(s["granted"] for s in phases["on"]["samples"]),
               "receipts_received": len(phases["on"]["receipts"]),
               "anchors": phases["on"].get("anchors"), "anchor_gas": phases["on"].get("anchor_gas"),
               "onchain": phases["on"].get("onchain"), "verify": phases["on"].get("verify")}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("warm_off", "warm_on", "granted_off", "granted_on",
                                               "receipts_received", "anchor_gas")}, indent=2))
    print("verify:", json.dumps(summary["verify"]))
    print("onchain match:", (summary["onchain"] or {}).get("matches_last_local_anchor"))
    print("results:", out_dir)


if __name__ == "__main__":
    main()
