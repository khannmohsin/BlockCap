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

def bundle(node_id: str, node_name: str, node_type: str, pubkey_path: str, privkey_path: str,
           rpc_url: str, node_url: str, wants_validator: bool) -> dict:
    
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
        "node_url": node_url,
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
        elif cmd == "bundle":
            # bundle <node_id> <node_name> <node_type> <pubkey_path> <privkey_path> <rpc_url> <wants_validator:true|false>
            _, _, node_id, node_name, node_type, pub_p, priv_p, rpc, node_url, wants = sys.argv
            wants_bool = str(wants).lower() == "true"
            b = bundle(node_id, node_name, node_type, pub_p, priv_p, rpc, node_url, wants_bool)
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