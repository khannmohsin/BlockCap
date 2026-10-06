#!/usr/bin/env python3
"""Register a generated fixture set and verify its latency distribution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import requests


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--fixtures-dir", type=Path, required=True)
    parser.add_argument("--condition", default="cold", choices=("cold",))
    args = parser.parse_args()

    manifest = json.loads((args.fixtures_dir / "manifest.json").read_text())
    fixtures = [json.loads((args.fixtures_dir / name).read_text()) for name in manifest["fixtures"]]
    if len(fixtures) != int(manifest["count"]):
        raise RuntimeError("fixture manifest count does not match fixture files")
    results: list[dict[str, Any]] = []
    for fixture in fixtures:
        response = requests.post(
            args.host.rstrip("/") + "/register-node",
            json=fixture,
            headers={"X-Latency-Condition": args.condition},
            timeout=180,
        )
        payload = response.json()
        results.append({"node_id": fixture["node_id"], "status_code": response.status_code, "payload": payload})
        if response.status_code >= 300:
            raise RuntimeError(f"registration failed for {fixture['node_id']}: {response.text}")

    summary = requests.get(args.host.rstrip("/") + "/metrics/latency", timeout=30).json()
    rows = [
        row for key, row in (summary.get("summary") or {}).items()
        if key.startswith("registerNode|") and row.get("condition") == args.condition
    ]
    if len(rows) != 1 or int(rows[0].get("count", 0)) != len(fixtures):
        raise RuntimeError(f"registerNode summary mismatch: expected {len(fixtures)}, got {rows}")

    output = args.fixtures_dir / "registration_results.json"
    output.write_text(json.dumps({"requested": len(fixtures), "results": results, "summary": rows[0]}, indent=2, sort_keys=True))
    print(json.dumps({"requested": len(fixtures), "summary": rows[0], "output": str(output)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
