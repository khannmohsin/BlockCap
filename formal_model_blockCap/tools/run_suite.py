#!/usr/bin/env python3
"""Run a suite of Alloy commands against a frozen model and record results.

Usage: tools/run_suite.py suites/<suite>.json [--jobs N] [--budget SECONDS]

Manifest format (JSON):
{
  "model": "models/blockcap_final.als",
  "out": "results_final/main",
  "scopes": {"main": "for ...", "small": "for ..."},
  "default_timeout": 1800,
  "jobs": [
    {"name": "P1_TokenUniqueness", "kind": "check", "expect": "holds", "scope": "main"},
    {"name": "Reach_DelegationChainDepth2", "kind": "run", "expect": "reachable", "scope": "main"}
  ]
}
"kind": "check" -> verdict UNSAT = holds, SAT = counterexample
"kind": "run"   -> verdict SAT = reachable, UNSAT = not reachable
A job may set "label" (unique id; default = name), "timeout", or an inline
"scope_str" instead of a named scope.

For each job a standalone .als (model body + one command) is generated, so the
model file itself carries no commands. SAT results are re-run as XML and
decoded with tools/decode_trace.py. Writes results.csv, results.md and
run_meta.json to the output directory.
"""
import argparse
import concurrent.futures as cf
import csv
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
JAR = ROOT / "tools" / "org.alloytools.alloy.dist.jar"
DECODE = ROOT / "tools" / "decode_trace.py"


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def expected_ok(kind, expect, verdict):
    if verdict not in ("SAT", "UNSAT"):
        return None
    if kind == "run":
        return (verdict == "SAT") == (expect == "reachable")
    return (verdict == "UNSAT") == (expect == "holds")


def meaning(kind, verdict):
    if verdict not in ("SAT", "UNSAT"):
        return verdict
    if kind == "run":
        return "reachable" if verdict == "SAT" else "not reachable"
    return "holds (no counterexample)" if verdict == "UNSAT" else "counterexample"


def run_job(job, model_text, out, deadline):
    label = job["label"]
    d = out / label
    d.mkdir(parents=True, exist_ok=True)
    als = d / f"{label}.als"
    als.write_text(model_text.rstrip() + f"\n\n{job['kind']} {job['name']}\n  {job['scope_str']}\n")
    remaining = deadline - time.time()
    if remaining <= 5:
        return {**job, "verdict": "not-run", "secs": 0}
    timeout = job["timeout"] if remaining == float("inf") else min(job["timeout"], int(remaining))
    t0 = time.time()
    try:
        p = subprocess.run(["java", "-jar", str(JAR), "exec", "-n", "-q", "-f", "-c", "0",
                            "-o", str(d / "json"), "-t", "json", str(als)],
                           capture_output=True, text=True, timeout=timeout)
        secs = round(time.time() - t0, 1)
        (d / "alloy.log").write_text(p.stdout + p.stderr)
        if p.returncode != 0:
            return {**job, "verdict": "ERROR", "secs": secs}
        verdict = "SAT" if any((d / "json").glob("*-solution-0.json")) else "UNSAT"
    except subprocess.TimeoutExpired:
        return {**job, "verdict": "TIMEOUT", "secs": timeout}
    res = {**job, "verdict": verdict, "secs": secs}
    if verdict == "SAT":  # decode the instance / counterexample
        subprocess.run(["java", "-jar", str(JAR), "exec", "-n", "-q", "-f", "-c", "0",
                        "-o", str(d / "xml"), "-t", "xml", str(als)],
                       capture_output=True, text=True, timeout=max(60, job["timeout"]))
        xs = sorted((d / "xml").glob("*-solution-0.xml"))
        if xs:
            txt = subprocess.run([sys.executable, str(DECODE), str(xs[0])],
                                 capture_output=True, text=True).stdout
            (d / "trace.txt").write_text(txt)
            res["trace"] = os.path.relpath(d / "trace.txt", ROOT)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--budget", type=int, default=0, help="global wall-clock budget in seconds (0 = none)")
    a = ap.parse_args()
    mpath = ROOT / a.manifest
    m = json.loads(mpath.read_text())
    model = ROOT / m["model"]
    model_text = model.read_text()
    out = ROOT / m["out"]
    out.mkdir(parents=True, exist_ok=True)
    jobs = []
    for j in m["jobs"]:
        j = dict(j)
        j.setdefault("label", j["name"])
        j.setdefault("timeout", m.get("default_timeout", 1800))
        j["scope_str"] = j.get("scope_str") or m["scopes"][j["scope"]]
        jobs.append(j)
    labels = [j["label"] for j in jobs]
    assert len(labels) == len(set(labels)), "duplicate job labels"
    start = time.time()
    deadline = start + a.budget if a.budget else float("inf")
    results = []
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        futs = [ex.submit(run_job, j, model_text, out, deadline) for j in jobs]
        for f in cf.as_completed(futs):
            r = f.result()
            r["ok"] = expected_ok(r["kind"], r["expect"], r["verdict"])
            results.append(r)
            flag = {True: "as expected", False: "UNEXPECTED", None: ""}[r["ok"]]
            print(f"{r['verdict']:8} {r['secs']:>7}s  {r['label']:46} {flag}", flush=True)
    order = {l: i for i, l in enumerate(labels)}
    results.sort(key=lambda r: order[r["label"]])
    fields = ["label", "name", "kind", "expect", "scope", "verdict", "secs", "ok", "trace", "scope_str"]
    with open(out / "results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)
    lines = ["| Command | Kind | Scope | Verdict | Meaning | Time (s) | As expected |",
             "|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['label']} | {r['kind']} | {r.get('scope', 'custom')} | {r['verdict']} | "
                     f"{meaning(r['kind'], r['verdict'])} | {r['secs']} | "
                     f"{ {True: 'yes', False: '**NO**', None: '—'}[r['ok']] } |")
    (out / "results.md").write_text("\n".join(lines) + "\n")
    java = subprocess.run(["java", "-version"], capture_output=True, text=True).stderr.splitlines()[0]
    alloy = subprocess.run(["java", "-jar", str(JAR), "version"], capture_output=True, text=True).stdout.strip()
    meta = {
        "date_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "alloy": alloy, "java": java,
        "model": m["model"], "model_sha256": sha256(model),
        "manifest": a.manifest, "manifest_sha256": sha256(mpath),
        "jar_sha256": sha256(JAR),
        "jobs": a.jobs, "budget_s": a.budget, "wall_s": round(time.time() - start, 1),
        "scopes": m["scopes"],
        "unexpected": [r["label"] for r in results if r["ok"] is False],
        "not_completed": [r["label"] for r in results if r["verdict"] not in ("SAT", "UNSAT")],
    }
    (out / "run_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps({k: meta[k] for k in ("model_sha256", "wall_s", "unexpected", "not_completed")}, indent=2))


if __name__ == "__main__":
    main()
