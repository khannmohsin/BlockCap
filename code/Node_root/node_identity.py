#!/usr/bin/env python3
"""
node_identity.py
- NO HTTP. Only key handling and signing.
- Prints values to stdout so your shell script can consume them.
- Can output a full JSON bundle and write node-details.json.

Commands:
  pubkey <key_path>
  address <private_key_path>
  sign <node_id> <node_name> <node_type> <public_key> <private_key_path>
  sign-request-proof <from_signature> <to_signature> <method> <resource_path> <nonce_ms> <private_key_path> [extra_fields_json]
  bundle <node_id> <node_name> <node_type> <pubkey_path> <privkey_path> <rpc_url> <wants_validator:true|false>
"""

import json
import os
import subprocess
import sys
from eth_keys import keys
from eth_utils import keccak


def _read_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read().strip()

def load_public_key(key_path: str) -> str:
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Public Key File Not Found: {key_path}")
    return _read_file(key_path)

def get_address(private_key_path: str) -> str:
    """Uses besu to derive 0x address from the private key file."""
    cmd = ["besu", "public-key", "export-address", f"--node-private-key-file={private_key_path}"]
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if p.returncode != 0:
        raise RuntimeError(p.stderr or "besu export-address failed")
    return p.stdout.strip().split("\n")[-1]

def sign_identity(node_id: str, node_name: str, node_type: str, public_key: str, private_key_path: str) -> str:
    """Matches orchestrator.verify_signature payload hashing."""
    message_dict = {
        "node_id": node_id,
        "node_name": node_name,
        "node_type": node_type,
        "public_key": public_key,
    }
    message_json = json.dumps(message_dict, sort_keys=True)
    digest = keccak(text=message_json)

    pk_hex = _read_file(private_key_path)
    if pk_hex.startswith("0x"):
        pk_hex = pk_hex[2:]
    priv = keys.PrivateKey(bytes.fromhex(pk_hex))
    sig = priv.sign_msg_hash(digest)
    return sig.to_hex()

REQUEST_PROOF_DOMAIN = "blockcap-request-proof-v1"

def sign_request_proof(from_signature: str, to_signature: str, method: str,
                        resource_path: str, nonce_ms: int, private_key_path: str,
                        extra_fields: dict | None = None) -> str:
    """Proof-of-possession signature for one /access (or /revoke-grant)
    request. Matches Orchestrator.verify_request_proof's message hashing
    exactly -- callers (real clients, load_test.py) must sign fresh per
    request; this is what proves the caller holds from_signature's private
    key for *this* request, not just knowledge of the (public)
    from_signature string itself.

    `extra_fields` must match, field for field, whatever the daemon binds
    for this specific route (e.g. /access's expiry_secs, allow_delegation,
    delegation_depth, audit) -- a mismatch here is a verification failure,
    not a silently-ignored extra field, by design: this is what prevents a
    network attacker from altering those fields on a signed request without
    invalidating the proof."""
    message_dict = {
        "domain": REQUEST_PROOF_DOMAIN,
        "from_signature": from_signature,
        "to_signature": to_signature,
        "method": (method or "").upper(),
        "resource_path": resource_path,
        "nonce_ms": int(nonce_ms),
        "extra": extra_fields or {},
    }
    message_json = json.dumps(message_dict, sort_keys=True)
    digest = keccak(text=message_json)

    pk_hex = _read_file(private_key_path)
    if pk_hex.startswith("0x"):
        pk_hex = pk_hex[2:]
    priv = keys.PrivateKey(bytes.fromhex(pk_hex))
    sig = priv.sign_msg_hash(digest)
    return sig.to_hex()

def bundle(node_id: str, node_name: str, node_type: str, pubkey_path: str, privkey_path: str,
           rpc_url: str, wants_validator: bool) -> dict:
    public_key = load_public_key(pubkey_path)
    address = get_address(privkey_path)
    signature = sign_identity(node_id, node_name, node_type, public_key, privkey_path)
    return {
        "node_id": node_id,
        "node_name": node_name,
        "node_type": node_type,
        "public_key": public_key,
        "address": address,
        "rpcURL": rpc_url,
        "signature": signature,
        "wants_validator": bool(wants_validator),
    }

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    try:
        if cmd == "pubkey":
            print(load_public_key(sys.argv[2]))
        elif cmd == "address":
            print(get_address(sys.argv[2]))
        elif cmd == "sign":
            # sign <node_id> <node_name> <node_type> <public_key> <private_key_path>
            _, _, node_id, node_name, node_type, public_key, priv = sys.argv
            print(sign_identity(node_id, node_name, node_type, public_key, priv))
        elif cmd == "sign-request-proof":
            # sign-request-proof <from_signature> <to_signature> <method> <resource_path> <nonce_ms> <private_key_path> [extra_fields_json]
            # extra_fields_json must match whatever the target route binds
            # (e.g. for /access: '{"expiry_secs":900,"allow_delegation":false,"delegation_depth":0,"audit":true}');
            # omit it (or pass '{}') for routes with no extra bound fields, like /revoke-grant.
            if len(sys.argv) == 9:
                _, _, from_sig, to_sig, method, resource_path, nonce_ms, priv, extra_json = sys.argv
                extra = json.loads(extra_json)
            else:
                _, _, from_sig, to_sig, method, resource_path, nonce_ms, priv = sys.argv
                extra = {}
            print(sign_request_proof(from_sig, to_sig, method, resource_path, int(nonce_ms), priv, extra_fields=extra))
        elif cmd == "bundle":
            # bundle <node_id> <node_name> <node_type> <pubkey_path> <privkey_path> <rpc_url> <wants_validator:true|false>
            _, _, node_id, node_name, node_type, pub_p, priv_p, rpc, wants = sys.argv
            wants_bool = str(wants).lower() == "true"
            b = bundle(node_id, node_name, node_type, pub_p, priv_p, rpc, wants_bool)
            # write node-details.json beside this file
            out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "node-details.json")
            with open(out_path, "w") as f:
                json.dump(b, f, indent=2)
            print(json.dumps(b))  # emit JSON for caller
        else:
            print(__doc__)
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()