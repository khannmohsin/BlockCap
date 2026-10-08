"""Tests for the signed, hash-chained, on-chain-anchored audit log."""
import json
import threading
from pathlib import Path

import pytest
from eth_keys import keys

import audit_log
from audit_log import AuditLog, load, verify

KEY = "0x" + "11" * 32
NODE = keys.PrivateKey(bytes.fromhex("11" * 32)).public_key.to_checksum_address()


def decision(i, granted=True, cache_hit=False):
    return {"from_sig": f"subj{i}", "to_sig": "obj", "method": "GET", "resource": "/temp",
            "policy_id": 1, "op": "READ", "granted": granted,
            "reason": "granted" if granted else "grant_revoked", "cache_hit": cache_hit,
            "nonce_ms": 1000 + i, "request_proof": f"0xproof{i}"}


def make(tmp_path, **kw):
    return AuditLog(tmp_path / "audit.jsonl", KEY, **kw)


def test_entries_form_a_signed_hash_chain(tmp_path):
    log = make(tmp_path)
    receipts = [log.append(decision(i, granted=i % 2 == 0)) for i in range(1, 6)]
    entries = load(log.path)
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]
    assert entries[0]["prev"] == audit_log.GENESIS
    assert all(entries[i]["prev"] == entries[i - 1]["hash"] for i in range(1, 5))
    assert all(e["node"] == NODE for e in entries)
    report = verify(entries, [], receipts)
    assert report["ok"], report
    assert report["unanchored_tail"] == 5


def test_denials_and_cache_hits_are_recorded(tmp_path):
    log = make(tmp_path)
    log.append(decision(1, granted=False))
    log.append(decision(2, granted=True, cache_hit=True))
    e = load(log.path)
    assert e[0]["granted"] is False and e[0]["reason"] == "grant_revoked"
    assert e[1]["cache_hit"] is True


@pytest.mark.parametrize("tamper, expected", [
    ("edit", "hash_mismatch"),
    ("delete", "seq_gap_or_reorder"),
    ("reorder", "seq_gap_or_reorder"),
    ("forge_sig", "bad_signature"),
])
def test_tampering_is_detected(tmp_path, tamper, expected):
    log = make(tmp_path)
    for i in range(1, 5):
        log.append(decision(i))
    e = load(log.path)
    if tamper == "edit":
        e[1]["granted"] = False                       # flip a recorded decision
    elif tamper == "delete":
        del e[1]
    elif tamper == "reorder":
        e[1], e[2] = e[2], e[1]
    elif tamper == "forge_sig":
        other = keys.PrivateKey(bytes.fromhex("22" * 32))
        e[1]["sig"] = "0x" + other.sign_msg_hash(bytes.fromhex(e[1]["hash"][2:])).to_bytes().hex()
    report = verify(e, [])
    assert not report["ok"]
    assert any(p.startswith(expected) for p in report["problems"]), report


def test_rewriting_history_breaks_the_anchored_root(tmp_path):
    log = make(tmp_path)
    for i in range(1, 4):
        log.append(decision(i))
    anchored = {"seq": 3, "root": log.head}
    # The node rewrites entry 2 and recomputes a self-consistent chain and signatures.
    e = load(log.path)
    rewritten = make(tmp_path / "rewrite")
    rewritten.append(decision(1))
    d2 = decision(2); d2["granted"] = False
    rewritten.append(d2)
    rewritten.append(decision(3))
    forged = load(rewritten.path)
    assert verify(forged, [])["ok"]                   # internally consistent ...
    report = verify(forged, [anchored])               # ... but not against the anchor
    assert not report["ok"]
    assert any(p.startswith("anchor_mismatch") for p in report["problems"])
    assert verify(e, [anchored])["ok"]


def test_receipt_missing_from_log_is_detected(tmp_path):
    log = make(tmp_path)
    r1 = log.append(decision(1))
    r2 = log.append(decision(2))
    e = load(log.path)[:1]                            # node drops the second decision
    report = verify(e, [], [r1, r2])
    assert not report["ok"]
    assert any(p.startswith("receipt_not_in_log seq 2") for p in report["problems"])


def test_anchoring_triggers_every_n_entries(tmp_path):
    calls = []
    done = threading.Event()

    def anchor(root, seq):
        calls.append((root, seq))
        done.set()
        return "0xtx"

    log = make(tmp_path, anchor_fn=anchor, anchor_every=3, anchor_interval_s=3600)
    log.append(decision(1))
    log.append(decision(2))
    assert not calls
    log.append(decision(3))
    assert done.wait(5)
    assert calls == [(load(log.path)[2]["hash"], 3)]
    anchors = load(log.anchors_path)
    assert anchors[0]["seq"] == 3 and anchors[0]["tx"] == "0xtx"
    assert verify(load(log.path), anchors)["ok"]


def test_resumes_chain_after_restart(tmp_path):
    log = make(tmp_path)
    log.append(decision(1))
    log.append(decision(2))
    log2 = make(tmp_path)                             # daemon restart
    assert (log2.seq, log2.head) == (2, log.head)
    log2.append(decision(3))
    assert verify(load(log2.path), [])["ok"]


# ----- orchestrator integration -----
def test_access_flow_attaches_receipt_and_logs_every_outcome(tmp_path):
    import orchestrator
    cached = {"ok": True, "granted": True, "op": "READ", "policyId": 1}

    def decide(self, from_sig, to_sig, http_method, resource_path, expiry_secs=900,
               allow_delegation=False, delegation_depth=0, audit=True, nonce_ms=None, request_proof=None):
        if from_sig == "denied":
            return {"ok": False, "why": "grant_revoked"}
        self.__dict__["_decision_ctx"].cached = from_sig == "cached"
        return cached

    o = orchestrator.Orchestrator.__new__(orchestrator.Orchestrator)
    o._access_flow_decide = decide.__get__(o)
    o._audit_log = make(tmp_path)
    out1 = o.access_flow("subj", "obj", "GET", "/temp", nonce_ms=5, request_proof="0xp")
    out2 = o.access_flow("denied", "obj", "GET", "/temp")
    out3 = o.access_flow("cached", "obj", "GET", "/temp")
    assert out1["audit_receipt"]["seq"] == 1
    assert out2["ok"] is False and out2["audit_receipt"]["seq"] == 2
    assert "audit_receipt" not in cached              # cached decision object not mutated
    e = load(o._audit_log.path)
    assert [x["granted"] for x in e] == [True, False, True]
    assert [x["cache_hit"] for x in e] == [False, False, True]
    assert e[0]["nonce_ms"] == 5 and e[0]["request_proof"] == "0xp"
    assert verify(e, [], [out1["audit_receipt"], out2["audit_receipt"], out3["audit_receipt"]])["ok"]


def test_access_flow_fails_closed_when_log_unavailable(tmp_path):
    import orchestrator

    def decide(self, *a, **k):
        return {"ok": True, "granted": True}

    class Broken:
        def append(self, _):
            raise OSError("disk full")

    o = orchestrator.Orchestrator.__new__(orchestrator.Orchestrator)
    o._access_flow_decide = decide.__get__(o)
    o._audit_log = Broken()
    out = o.access_flow("subj", "obj", "GET", "/temp")
    assert out["ok"] is False and out["why"].startswith("audit_log_unavailable")


def test_access_flow_denies_when_log_required_but_not_initialised():
    import orchestrator

    def decide(self, *a, **k):
        return {"ok": True, "granted": True}

    o = orchestrator.Orchestrator.__new__(orchestrator.Orchestrator)
    o._access_flow_decide = decide.__get__(o)
    o._audit_log = None
    o._audit_required = True
    out = o.access_flow("subj", "obj", "GET", "/temp")
    assert out["ok"] is False and out["why"] == "audit_log_unavailable:not_initialised"


def test_only_one_anchor_in_flight(tmp_path):
    release = threading.Event()
    calls = []

    def slow_anchor(root, seq):
        calls.append(seq)
        release.wait(5)
        return "0xtx"

    log = make(tmp_path, anchor_fn=slow_anchor, anchor_every=2, anchor_interval_s=3600)
    for i in range(1, 8):              # many entries while the first anchor is pending
        log.append(decision(i))
    release.set()
    import time as _t
    _t.sleep(0.5)
    assert len(calls) == 1             # no extra anchors queued behind the pending one
