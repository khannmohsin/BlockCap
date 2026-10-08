"""Signed, hash-chained audit log of access decisions, anchored on-chain.

Every authorization decision the TEF makes (granted or denied, including
decisions served from the positive-decision cache) is appended as one JSON
line. Each entry commits to its predecessor (`prev`), so the log is a hash
chain; the entry hash is signed with the enforcing node's identity key, and
the signed hash is returned to the requester as a receipt.

Periodically (every `anchor_every` entries or `anchor_interval_s` seconds,
whichever comes first) the current head hash is committed to the contract via
`anchorAuditRoot(root, seq)`. After that, altering, removing, or reordering any
entry at or before `seq` is detectable against the on-chain root.

Non-repudiation, concretely:
  - the requester cannot deny a request: its signed request proof is in the
    entry (`request_proof`, `nonce_ms`);
  - the enforcing node cannot deny a decision: the requester holds a receipt
    signed by the node's key over the entry hash;
  - the node cannot silently rewrite history once a root covering the entry
    is anchored.
Entries after the last anchor are protected by the receipts until the next
anchor.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from eth_keys import keys
from eth_utils import keccak

GENESIS = "0x" + "00" * 32

# Fields hashed into an entry, in canonical (sorted-key, compact) JSON.
ENTRY_FIELDS = (
    "seq", "prev", "ts_ms", "node", "from_sig", "to_sig", "method", "resource",
    "policy_id", "op", "granted", "reason", "cache_hit", "nonce_ms", "request_proof",
)


def canonical(body: Dict[str, Any]) -> bytes:
    return json.dumps({k: body.get(k) for k in ENTRY_FIELDS}, sort_keys=True,
                      separators=(",", ":")).encode()


def entry_hash(body: Dict[str, Any]) -> str:
    return "0x" + keccak(canonical(body)).hex()


def recover_signer(hash_hex: str, sig_hex: str) -> str:
    sig = keys.Signature(bytes.fromhex(sig_hex.removeprefix("0x")))
    return sig.recover_public_key_from_msg_hash(bytes.fromhex(hash_hex.removeprefix("0x"))).to_checksum_address()


class AuditLog:
    def __init__(self, path: Path, private_key_hex: str,
                 anchor_fn: Optional[Callable[[str, int], Any]] = None,
                 anchor_every: int = 50, anchor_interval_s: float = 30.0,
                 anchors_path: Optional[Path] = None) -> None:
        self.path = Path(path)
        self.anchors_path = Path(anchors_path) if anchors_path else self.path.with_suffix(".anchors.jsonl")
        self._key = keys.PrivateKey(bytes.fromhex(private_key_hex.strip().removeprefix("0x")))
        self.node = self._key.public_key.to_checksum_address()
        self._anchor_fn = anchor_fn
        self.anchor_every = max(1, int(anchor_every))
        self.anchor_interval_s = float(anchor_interval_s)
        self._lock = threading.Lock()
        self._anchor_lock = threading.Lock()
        self._anchor_pending = False  # one anchor in flight at a time
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq, self.head = self._resume()
        self.anchored_seq = self._last_anchored_seq()
        self._last_anchor_time = time.time()

    # ----- state -----
    def _resume(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last = None
        with self.path.open() as fh:
            for line in fh:
                if line.strip():
                    last = line
        rec = json.loads(last)
        return int(rec["seq"]), rec["hash"]

    def _last_anchored_seq(self) -> int:
        if not self.anchors_path.exists():
            return 0
        seqs = [json.loads(l)["seq"] for l in self.anchors_path.read_text().splitlines() if l.strip()]
        return max(seqs) if seqs else 0

    # ----- append -----
    def append(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Append one decision; return the signed receipt for the requester."""
        with self._lock:
            body = {k: decision.get(k) for k in ENTRY_FIELDS}
            body.update(seq=self.seq + 1, prev=self.head, ts_ms=int(time.time() * 1000), node=self.node)
            h = entry_hash(body)
            sig = "0x" + self._key.sign_msg_hash(bytes.fromhex(h[2:])).to_bytes().hex()
            rec = {**body, "hash": h, "sig": sig}
            with self.path.open("a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.seq, self.head = body["seq"], h
            due = (not self._anchor_pending and self._anchor_fn is not None and
                   (self.seq - self.anchored_seq >= self.anchor_every or
                    time.time() - self._last_anchor_time >= self.anchor_interval_s))
            if due:
                self._anchor_pending = True
        if due:
            threading.Thread(target=self._anchor_bg, daemon=True).start()
        return {"seq": body["seq"], "hash": h, "prev": body["prev"], "node": self.node, "sig": sig}

    # ----- anchoring -----
    def _anchor_bg(self) -> None:
        try:
            self.anchor_now()
        except Exception as exc:  # retried on a later append
            print(f"[audit] anchoring failed: {exc}")
        finally:
            with self._lock:
                self._anchor_pending = False

    def anchor_now(self) -> Optional[Dict[str, Any]]:
        """Commit the current head on-chain (no-op if nothing new)."""
        if self._anchor_fn is None:
            return None
        with self._anchor_lock:
            with self._lock:
                seq, head = self.seq, self.head
            if seq <= self.anchored_seq:
                return None
            t0 = time.time()
            tx = self._anchor_fn(head, seq)
            rec = {"seq": seq, "root": head, "tx": tx, "ts_ms": int(t0 * 1000),
                   "latency_ms": round((time.time() - t0) * 1000, 3)}
            with self.anchors_path.open("a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            self.anchored_seq = seq
            self._last_anchor_time = time.time()
            return rec


# ----- verification -----
def load(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def verify(entries: List[Dict[str, Any]], anchors: List[Dict[str, Any]],
           receipts: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Check chain linkage, entry hashes, node signatures, anchored roots, and
    (optionally) that every requester-held receipt is present in the log.
    `anchors` are (seq, root) records, e.g. read from AuditRootAnchored events."""
    problems: List[str] = []
    by_seq: Dict[int, Dict[str, Any]] = {}
    prev = GENESIS
    for i, e in enumerate(entries, 1):
        if e.get("seq") != i:
            problems.append(f"seq_gap_or_reorder at position {i}: seq={e.get('seq')}")
        if e.get("prev") != prev:
            problems.append(f"broken_link at seq {e.get('seq')}")
        h = entry_hash(e)
        if h != e.get("hash"):
            problems.append(f"hash_mismatch at seq {e.get('seq')}")
        try:
            if recover_signer(e["hash"], e["sig"]) != e.get("node"):
                problems.append(f"bad_signature at seq {e.get('seq')}")
        except Exception:
            problems.append(f"bad_signature at seq {e.get('seq')}")
        by_seq[e.get("seq")] = e
        prev = e.get("hash")
    for a in anchors:
        e = by_seq.get(int(a["seq"]))
        if e is None:
            problems.append(f"anchor_beyond_log seq {a['seq']}")
        elif e["hash"] != a["root"]:
            problems.append(f"anchor_mismatch at seq {a['seq']}")
    for r in receipts or []:
        e = by_seq.get(int(r["seq"]))
        if e is None or e["hash"] != r["hash"]:
            problems.append(f"receipt_not_in_log seq {r['seq']}")
        else:
            try:
                if recover_signer(r["hash"], r["sig"]) != r["node"]:
                    problems.append(f"receipt_bad_signature seq {r['seq']}")
            except Exception:
                problems.append(f"receipt_bad_signature seq {r['seq']}")
    last_anchor = max((int(a["seq"]) for a in anchors), default=0)
    return {"ok": not problems, "problems": problems, "entries": len(entries),
            "anchored_through": last_anchor, "unanchored_tail": max(0, len(entries) - last_anchor)}


if __name__ == "__main__":  # python3 audit_log.py <log.jsonl> [anchors.jsonl]
    import sys
    log = Path(sys.argv[1])
    anc = Path(sys.argv[2]) if len(sys.argv) > 2 else log.with_suffix(".anchors.jsonl")
    report = verify(load(log), load(anc) if anc.exists() else [])
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["ok"] else 1)
