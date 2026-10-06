import asyncio
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import aiohttp

sys.path.insert(0, "/Users/khannmohsin/VSCode Projects/BlockCap/code/Node_root")
from node_identity import sign_request_proof

ROOT_SIG = "0xd798d81cdea9f8fb3cd084e5a5f4b839fc89ae8591025c840122b126405a588c3d4cab8e0f1ad91a886e6a1b804760437d483bd73f765f61d05032028a05b57b00"
ROOT_KEY = "/Users/khannmohsin/VSCode Projects/BlockCap/code/runtime/generated/r2-c11-openloop/root/data/key.priv"
FOG1_SIG = "0xbc2aa1eca2394c660437281fff3cc34359bed6b4d519dc0c3cbf986945e016587ab342432d28bf0948fe108fd33e1e536fec69a62679f1b2e95c7584cd46ce2a01"
FOG1_API = "http://127.0.0.1:52461"
EDGE1_SIG = "0x8f1c884e8d408f65c9ed46fbcc140732702fbe3b4ad1039d5cd3dbf2e0035ca6023d3c8389b5d6cfbd793b8d201baf285983d4a0922a2482b16fe08455bda44500"
EDGE1_API = "http://127.0.0.1:58042"

METHOD = "GET"
PATH = "/openloop-test"

_ctr = [0]
_ctr_lock = asyncio.Lock()
executor = ThreadPoolExecutor(max_workers=8)


def _next_nonce_sync(offset):
    return int(time.time() * 1000) * 1_000_000 + offset


def _build_signed_body_sync(to_sig, nonce_offset):
    nonce_ms = _next_nonce_sync(nonce_offset)
    extra = {"expiry_secs": 3600, "allow_delegation": False, "delegation_depth": 0, "audit": True}
    proof = sign_request_proof(ROOT_SIG, to_sig, METHOD, PATH, nonce_ms, ROOT_KEY, extra_fields=extra)
    return {
        "from_signature": ROOT_SIG, "to_signature": to_sig, "method": METHOD,
        "resource_path": PATH, "expiry_secs": 3600, "allow_delegation": False,
        "delegation_depth": 0, "audit": True, "nonce_ms": nonce_ms, "request_proof": proof,
    }


async def fire_one(session, api, to_sig, nonce_offset, results):
    loop = asyncio.get_running_loop()
    body = await loop.run_in_executor(executor, _build_signed_body_sync, to_sig, nonce_offset)
    t0 = time.perf_counter()
    err_detail = None
    resp_body = None
    try:
        async with session.post(f"{api}/access", json=body, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            resp_body = await resp.text()
            status = resp.status
    except Exception as e:
        status = -1
        err_detail = f"{type(e).__name__}: {e}"
    t1 = time.perf_counter()
    results.append({
        "status": status, "latency_ms": (t1 - t0) * 1000,
        "err_detail": err_detail,
        "resp_body": (resp_body[:200] if resp_body and status not in (200,) else None),
    })


async def run_open_loop(api, to_sig, rate_hz, duration_s, label):
    """Open-loop: fire a new request every 1/rate_hz seconds, regardless of
    whether earlier requests have completed -- offered load is decoupled
    from completed load, unlike a closed-loop (N-concurrent-slots) generator."""
    interval = 1.0 / rate_hz
    results = []
    offered = 0
    start = time.perf_counter()
    tasks = []
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        next_fire = start
        nonce_offset = 0
        while (time.perf_counter() - start) < duration_s:
            now = time.perf_counter()
            if now >= next_fire:
                nonce_offset += 1
                tasks.append(asyncio.create_task(fire_one(session, api, to_sig, nonce_offset, results)))
                offered += 1
                next_fire += interval
            else:
                await asyncio.sleep(max(0.0, next_fire - now))
        # let in-flight requests drain (bounded wait)
        if tasks:
            await asyncio.wait(tasks, timeout=15)
    elapsed = time.perf_counter() - start

    statuses = [r["status"] for r in results]
    completed_200 = sum(1 for s in statuses if s == 200)
    throttled_429 = sum(1 for s in statuses if s == 429)
    other_errors = sum(1 for s in statuses if s not in (200, 429))
    completed_total = len(results)
    latencies = [r["latency_ms"] for r in results if r["status"] == 200]
    from collections import Counter
    error_breakdown = Counter()
    for r in results:
        if r["status"] not in (200, 429):
            key = r["err_detail"] or f"http_{r['status']}:{(r['resp_body'] or '')[:120]}"
            error_breakdown[key] += 1
    summary = {
        "label": label,
        "target": api,
        "offered_rate_hz": rate_hz,
        "duration_s": round(elapsed, 3),
        "offered_requests": offered,
        "completed_requests": completed_total,
        "granted_200": completed_200,
        "throttled_429": throttled_429,
        "other_errors": other_errors,
        "error_breakdown": dict(error_breakdown.most_common(5)),
        "achieved_offered_rate_hz": round(offered / elapsed, 2),
        "achieved_granted_rate_hz": round(completed_200 / elapsed, 2),
        "throttle_fraction": round(throttled_429 / completed_total, 4) if completed_total else None,
        "p50_granted_latency_ms": round(sorted(latencies)[len(latencies) // 2], 3) if latencies else None,
    }
    return summary, results


async def main():
    all_results = []
    raw_by_label = {}
    # Edge1: theta = 50 req/s. Test below, at, and above the token-bucket rate.
    for rate in (25, 50, 100):
        r, raw = await run_open_loop(EDGE1_API, EDGE1_SIG, rate, 8.0, f"edge1@{rate}Hz")
        print(json.dumps(r, indent=2))
        all_results.append(r)
        raw_by_label[r["label"]] = raw
        await asyncio.sleep(3)  # let bucket refill fully between runs

    # Fog1: theta = 100 req/s.
    for rate in (50, 100, 200):
        r, raw = await run_open_loop(FOG1_API, FOG1_SIG, rate, 8.0, f"fog1@{rate}Hz")
        print(json.dumps(r, indent=2))
        all_results.append(r)
        raw_by_label[r["label"]] = raw
        await asyncio.sleep(3)

    out_path = "/private/tmp/claude-501/-Users-khannmohsin-VSCode-Projects-BlockCap/scratchpad/r2c11_openloop_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    raw_path = "/private/tmp/claude-501/-Users-khannmohsin-VSCode-Projects-BlockCap/scratchpad/r2c11_openloop_raw.json"
    with open(raw_path, "w") as f:
        json.dump(raw_by_label, f, indent=2)
    print("wrote", out_path, "and", raw_path)


if __name__ == "__main__":
    asyncio.run(main())
