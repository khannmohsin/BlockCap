#!/usr/bin/env python3
import argparse
import json
import math
import statistics
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from pathlib import Path
from typing import Any

import requests

NODE_ROOT = Path(__file__).resolve().parents[1] / "Node_root"
if str(NODE_ROOT) not in sys.path:
    sys.path.insert(0, str(NODE_ROOT))


RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))
    return ordered[idx]


def summarize_latency_ms(latencies: list[float]) -> dict[str, float]:
    if not latencies:
        return {
            "mean_latency_ms": 0.0,
            "stddev_latency_ms": 0.0,
            "median_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
        }
    mean_ms = statistics.fmean(latencies) * 1000
    stddev_ms = (statistics.pstdev(latencies) * 1000) if len(latencies) > 1 else 0.0
    median_ms = statistics.median(latencies) * 1000
    p95_ms = percentile(latencies, 0.95) * 1000
    return {
        "mean_latency_ms": round(mean_ms, 3),
        "stddev_latency_ms": round(stddev_ms, 3),
        "median_latency_ms": round(median_ms, 3),
        "p95_latency_ms": round(p95_ms, 3),
    }


def resolve_request(host: str, operation: str, method: str | None, path_override: str | None, body: dict[str, Any] | None):
    path_map = {
        "health": ("GET", "/health"),
        "latency": ("GET", "/metrics/latency"),
        "access": ("POST", "/access"),
        "delegate": ("POST", "/delegate"),
        "expiryCheck": ("GET", "/expiry-check"),
        "registerNode": ("POST", "/register-node"),
        "revokeToken": ("POST", "/revoke-grant"),
        "grant": ("GET", "/grant"),
    }
    default_method, default_path = path_map.get(operation, ("GET", f"/{operation.lstrip('/')}"))
    req_method = (method or default_method).upper()
    req_path = path_override or default_path
    return req_method, host.rstrip("/") + req_path, body


def load_json(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    return json.loads(Path(path).read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description="Concurrent HTTP load test for BlockCap endpoints")
    parser.add_argument("--host", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--concurrency", type=int, required=True)
    parser.add_argument("--total-requests", type=int, default=500)
    parser.add_argument("--duration-cap", type=float, default=60.0)
    parser.add_argument("--method")
    parser.add_argument("--path")
    parser.add_argument("--body-file")
    parser.add_argument(
        "--raw-log",
        help="Optional path to append one JSON line per request (timestamp, status_code, latency_ms, ok). "
        "Enables recomputing throughput/percentiles independently of the summary written by this script.",
    )
    parser.add_argument(
        "--rate-limiter-disabled",
        action="store_true",
        help="Record in the summary that this run targeted a host with DISABLE_RATE_LIMITER=1 set "
        "(limiter-isolation run). Does not itself change server behaviour.",
    )
    parser.add_argument(
        "--signing-key-file",
        help="Path to the FROM node's private key file. Required for --operation access once request "
        "proof-of-possession is enforced (see Orchestrator.verify_request_proof): each request gets a "
        "fresh nonce_ms + request_proof signed with this key, since a static, unsigned body is no "
        "longer sufficient to authenticate as the subject.",
    )
    args = parser.parse_args()

    body = load_json(args.body_file)
    method, url, payload = resolve_request(args.host, args.operation, args.method, args.path, body)

    sign_request_proof = None
    _nonce_lock = threading.Lock()
    _nonce_counter = [0]

    def _next_nonce() -> int:
        # Pack a wall-clock ms timestamp with a monotonically increasing
        # counter so concurrent threads firing within the same millisecond
        # never generate identical nonces (which the server would otherwise
        # reject as a replay of each other). See verify_request_proof's
        # unpacking logic for the corresponding server-side half of this.
        with _nonce_lock:
            _nonce_counter[0] += 1
            counter = _nonce_counter[0]
        base_ms = int(time.time() * 1000)
        return base_ms * 1_000_000 + (counter % 1_000_000)

    if args.signing_key_file:
        from node_identity import sign_request_proof as _sign_request_proof
        sign_request_proof = _sign_request_proof
    elif args.operation == "access":
        print(
            "WARNING: --operation access with no --signing-key-file: every request will be "
            "rejected once the target enforces request proof-of-possession (request_proof_invalid).",
            file=sys.stderr,
        )
    session = requests.Session()
    # requests.Session()'s default HTTPAdapter pool_maxsize is 10 -- with
    # `concurrency` threads sharing one session, anything above that churns
    # connections (opened, used once, discarded) instead of reusing a small
    # pool, which manifests as spurious "Connection reset by peer" failures
    # under sustained concurrent load that look like a server-side outage but
    # are actually the load generator under-provisioning its own connection
    # pool. Size it to the actual concurrency so this measures the target's
    # real capacity, not requests/urllib3's default pool size.
    _pool_size = max(20, args.concurrency * 2)
    _adapter = requests.adapters.HTTPAdapter(pool_connections=_pool_size, pool_maxsize=_pool_size)
    session.mount("http://", _adapter)
    session.mount("https://", _adapter)
    lock = threading.Lock()
    latencies: list[float] = []
    success_latencies: list[float] = []
    throttled_latencies: list[float] = []
    error_latencies: list[float] = []
    raw_rows: list[dict[str, Any]] = []
    errors = 0
    throttled = 0
    non_throttle_errors = 0
    exception_count = 0
    granted_true_count = 0
    status_counts: Counter[str] = Counter()
    started = 0
    completed = 0
    start_time = time.monotonic()
    start_wall = time.time()
    deadline = start_time + args.duration_cap

    def fire_once():
        nonlocal errors, throttled, non_throttle_errors, exception_count, granted_true_count
        req_wall_start = time.time()
        req_start = time.perf_counter()
        status_code = None
        granted: bool | None = None
        req_payload = payload
        if sign_request_proof is not None and isinstance(payload, dict):
            req_payload = dict(payload)
            nonce_ms = _next_nonce()
            req_payload["nonce_ms"] = nonce_ms
            # Sign the *body's* "method" field (the resource operation being
            # requested, e.g. GET on the underlying resource), not the outer
            # HTTP verb used to call /access itself (always POST) -- these are
            # different fields and the server's verify_request_proof binds to
            # the former, matching what access_flow receives as http_method.
            # These must match access_flow's own defaults exactly when the
            # request body omits them -- the daemon binds the actual values
            # it resolves (default or explicit), not just what's present in
            # the body, so an omitted field here still needs its resolved
            # default signed over.
            req_payload["request_proof"] = sign_request_proof(
                req_payload.get("from_signature"),
                req_payload.get("to_signature"),
                req_payload.get("method"),
                req_payload.get("resource_path"),
                nonce_ms,
                args.signing_key_file,
                extra_fields={
                    "expiry_secs": int(req_payload.get("expiry_secs", 900)),
                    "allow_delegation": bool(req_payload.get("allow_delegation", False)),
                    "delegation_depth": int(req_payload.get("delegation_depth", 0)),
                    "audit": bool(req_payload.get("audit", True)),
                },
            )
        try:
            if method == "GET":
                resp = session.get(url, timeout=15)
            else:
                resp = session.request(method, url, json=req_payload, timeout=15)
            status_code = int(resp.status_code)
            ok = 200 <= resp.status_code < 300
            if ok:
                try:
                    body_json = resp.json()
                    granted = bool(body_json.get("granted", False))
                except Exception:
                    granted = None
        except Exception:
            ok = False
        elapsed = time.perf_counter() - req_start
        with lock:
            latencies.append(elapsed)
            raw_rows.append({
                "timestamp": req_wall_start,
                "status_code": status_code,
                "latency_ms": round(elapsed * 1000, 3),
                "ok": ok,
                "granted": granted,
            })
            if status_code is None:
                exception_count += 1
                error_latencies.append(elapsed)
            else:
                status_counts[str(status_code)] += 1
                if ok:
                    success_latencies.append(elapsed)
                    if granted:
                        granted_true_count += 1
                elif status_code == 429:
                    throttled_latencies.append(elapsed)
                else:
                    error_latencies.append(elapsed)
            if not ok:
                errors += 1
                if status_code == 429:
                    throttled += 1
                else:
                    non_throttle_errors += 1

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = set()
        while time.monotonic() < deadline and started < args.total_requests:
            while len(futures) < args.concurrency and started < args.total_requests and time.monotonic() < deadline:
                futures.add(pool.submit(fire_once))
                started += 1
            if not futures:
                break
            done, futures = wait(futures, return_when=FIRST_COMPLETED)
            completed += len(done)

        if futures:
            done, _ = wait(futures)
            completed += len(done)

    wall_seconds = max(0.001, time.monotonic() - start_time)
    all_latency = summarize_latency_ms(latencies)
    success_latency = summarize_latency_ms(success_latencies)
    throttled_latency = summarize_latency_ms(throttled_latencies)
    error_latency = summarize_latency_ms(error_latencies)
    throughput_rps = completed / wall_seconds

    result = {
        "host": args.host,
        "operation": args.operation,
        "method": method,
        "url": url,
        "concurrency": args.concurrency,
        "total_requests": started,
        "completed_requests": completed,
        "duration_seconds": round(wall_seconds, 3),
        **all_latency,
        "success_count": len(success_latencies),
        "success_count_note": "HTTP 2xx count, NOT the same as an authenticated, granted "
        "protected-operation count -- /access can return HTTP 200 with granted=false. "
        "Use granted_true_count for the latter when --operation access is used with a "
        "response body that includes a granted field.",
        "granted_true_count": granted_true_count,
        "success_mean_latency_ms": success_latency["mean_latency_ms"],
        "success_stddev_latency_ms": success_latency["stddev_latency_ms"],
        "success_median_latency_ms": success_latency["median_latency_ms"],
        "success_p95_latency_ms": success_latency["p95_latency_ms"],
        "throttled_mean_latency_ms": throttled_latency["mean_latency_ms"],
        "throttled_p95_latency_ms": throttled_latency["p95_latency_ms"],
        "error_mean_latency_ms": error_latency["mean_latency_ms"],
        "error_p95_latency_ms": error_latency["p95_latency_ms"],
        "throughput_rps": round(throughput_rps, 3),
        "error_count": errors,
        "throttled_count": throttled,
        "throttled_rate": round((throttled / completed), 4) if completed else 0.0,
        "throttled_rate_of_attempted": round((throttled / started), 4) if started else 0.0,
        "non_throttle_error_count": non_throttle_errors,
        "exception_count": exception_count,
        "status_counts": dict(sorted(status_counts.items())),
        "generator_loop_model": "closed-loop: each of `concurrency` in-flight slots waits for its "
        "response before the next request is submitted into that slot (ThreadPoolExecutor + "
        "wait(FIRST_COMPLETED)); N is in-flight request count, not a fixed arrival rate.",
        "rate_limiter_disabled": bool(args.rate_limiter_disabled),
        "start_wall_time": start_wall,
    }

    if args.raw_log:
        raw_log_path = Path(args.raw_log)
        raw_log_path.parent.mkdir(parents=True, exist_ok=True)
        with raw_log_path.open("w") as fh:
            for row in raw_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        result["raw_log_path"] = str(raw_log_path)
        result["raw_log_count"] = len(raw_rows)

    output_path = RESULTS_DIR / "load_test.json"
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
