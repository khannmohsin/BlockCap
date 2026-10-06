#!/usr/bin/env python3
"""Generate fresh, signed node-registration fixtures for a distribution run."""

from __future__ import annotations

import argparse
import json
import os
import secrets
from pathlib import Path
from typing import Any

from eth_keys import keys
from eth_utils import keccak


def _identity_signature(
    node_id: str,
    node_name: str,
    node_type: str,
    public_key: str,
    private_key: keys.PrivateKey,
) -> str:
    message = {
        "node_id": node_id,
        "node_name": node_name,
        "node_type": node_type,
        "public_key": public_key,
    }
    digest = keccak(text=json.dumps(message, sort_keys=True))
    return private_key.sign_msg_hash(digest).to_hex()


def _fixture(index: int, *, prefix: str, node_type: str, rpc_url: str) -> dict[str, Any]:
    private_key = keys.PrivateKey(secrets.token_bytes(32))
    public_key = private_key.public_key.to_hex()
    node_id = f"{prefix}-{index:03d}"
    node_name = f"{prefix.title()}-{index:03d}"
    address = "0x" + private_key.public_key.to_canonical_address().hex()
    return {
        "node_id": node_id,
        "node_name": node_name,
        "node_type": node_type,
        "public_key": public_key,
        "address": address,
        "rpcURL": rpc_url,
        "signature": _identity_signature(node_id, node_name, node_type, public_key, private_key),
        "wants_validator": False,
        "_private_key": "0x" + private_key.to_hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--prefix", default="EXPERIMENT-SENSOR")
    parser.add_argument("--node-type", default="Sensor", choices=("Sensor", "Actuator"))
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545")
    args = parser.parse_args()
    if args.count < 1:
        raise SystemExit("--count must be positive")

    args.output_dir.mkdir(parents=True, exist_ok=False)
    fixtures = [_fixture(i, prefix=args.prefix, node_type=args.node_type, rpc_url=args.rpc_url) for i in range(args.count)]
    for fixture in fixtures:
        private_key = fixture.pop("_private_key")
        path = args.output_dir / f"{fixture['node_id']}.json"
        path.write_text(json.dumps(fixture, indent=2, sort_keys=True))
        os.chmod(path, 0o600)
        key_path = args.output_dir / f"{fixture['node_id']}.key"
        key_path.write_text(private_key + "\n")
        os.chmod(key_path, 0o600)

    manifest = {
        "count": len(fixtures),
        "node_type": args.node_type,
        "prefix": args.prefix,
        "fixtures": [f"{fixture['node_id']}.json" for fixture in fixtures],
        "signature_scheme": "keccak(sorted JSON node_id/node_name/node_type/public_key), secp256k1 sign_msg_hash",
    }
    manifest_path = args.output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    os.chmod(manifest_path, 0o600)
    print(f"Generated {len(fixtures)} fresh registration fixtures in {args.output_dir}")


if __name__ == "__main__":
    main()
