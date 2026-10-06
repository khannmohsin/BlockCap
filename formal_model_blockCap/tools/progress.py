#!/usr/bin/env python3
"""Live progress bars for run_final.sh (read-only; does not affect the run).

Usage: python3 tools/progress.py          # refresh every 5 s, Ctrl+C to quit
       python3 tools/progress.py --once   # print once
       python3 tools/progress.py --suite rerun   # follow one suite (suites/rerun.json,
                                                 # log results_final/rerun.log)
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOG = ROOT / "results_final" / "run_final.log"
RESULT = re.compile(r"^(SAT|UNSAT|ERROR|TIMEOUT|not-run|KILLED|survived)\s+\S+s\s+(\S+)(.*)$")


def totals():
    main = len(json.loads((ROOT / "suites" / "main.json").read_text())["jobs"])
    scaling = len(json.loads((ROOT / "suites" / "scaling.json").read_text())["jobs"])
    sys.path.insert(0, str(ROOT / "tools"))
    import mutation_test  # noqa: E402
    mutation = sum(len(m[4]) for m in mutation_test.MUTANTS_FINAL)
    return {"MAIN": main, "MUTATION": mutation, "SCALING": scaling}


def parse():
    phases = {"MAIN": [], "MUTATION": [], "SCALING": []}
    current, start, ended = None, None, None
    if not LOG.exists():
        return phases, current, start, ended
    for line in LOG.read_text().splitlines():
        if line.startswith("== "):
            tag = line.split()[1]
            if tag == "START":
                start = line.split()[2]
            elif tag == "END":
                ended = line.split()[2]
                current = None
            elif tag in phases:
                current = tag
            continue
        m = RESULT.match(line)
        if m and current:
            phases[current].append((m.group(1), m.group(2), m.group(3).strip()))
    return phases, current, start, ended


def running():
    out = subprocess.run(["ps", "-axo", "etime=,args="], capture_output=True, text=True).stdout
    jobs = []
    for line in out.splitlines():
        if "dist.jar exec" in line:
            et = line.split()[0]
            als = re.search(r"([A-Za-z0-9_]+)\.als", line)
            jobs.append((et, als.group(1) if als else "?"))
    return jobs


def bar(done, total, width=34):
    total = max(total, 1)
    fill = int(width * min(done, total) / total)
    return "█" * fill + "░" * (width - fill) + f" {done:>3}/{total:<3} {100 * done // total:>3}%"


def render(tot):
    phases, current, start, ended = parse()
    lines = ["BlockCap final Alloy run" + (f"   started {start}" if start else "   (not started)"), ""]
    for name in ("MAIN", "MUTATION", "SCALING"):
        res = phases[name]
        state = "done" if (ended or (current and list(phases).index(current) > list(phases).index(name))) and res \
            else ("running" if current == name else "waiting")
        lines.append(f"{name:9} {bar(len(res), tot[name])}  {state}")
    done = sum(len(v) for v in phases.values())
    lines += ["", f"{'OVERALL':9} {bar(done, sum(tot.values()))}", ""]
    jobs = running()
    lines.append(f"Running now ({len(jobs)}):" if jobs else "Running now: none")
    for et, name in jobs:
        lines.append(f"  {et:>9}  {name}")
    flagged = [(p, r) for p, rs in phases.items() for r in rs
               if "UNEXPECTED" in r[2] or r[0] in ("ERROR", "TIMEOUT", "survived")]
    if flagged:
        lines += ["", "Attention:"]
        lines += [f"  [{p}] {r[0]:8} {r[1]} {r[2]}" for p, r in flagged]
    if ended:
        lines += ["", f"FINISHED {ended}"]
    return "\n".join(lines)


def render_suite(name):
    man = json.loads((ROOT / "suites" / f"{name}.json").read_text())
    total = len(man["jobs"])
    log = ROOT / "results_final" / f"{name}.log"
    res = []
    if log.exists():
        for line in log.read_text().splitlines():
            m = RESULT.match(line)
            if m:
                res.append((m.group(1), m.group(2), m.group(3).strip()))
    jobs = running()
    lines = [f"BlockCap suite '{name}'  (per-job limit {man.get('default_timeout', 0) // 60} min)", "",
             f"{'PROGRESS':9} {bar(len(res), total)}", ""]
    for v, lab, note in res:
        lines.append(f"  done     {v:8} {lab} {note}")
    for et, n in jobs:
        lines.append(f"  running  {et:>8} {n}")
    if not jobs and len(res) >= total:
        lines += ["", "FINISHED"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=5)
    ap.add_argument("--suite", help="follow a single suite, e.g. rerun")
    a = ap.parse_args()
    if a.suite:
        draw = lambda: render_suite(a.suite)
    else:
        tot = totals()
        draw = lambda: render(tot)
    if a.once:
        print(draw())
        return
    try:
        while True:
            sys.stdout.write("\033[2J\033[H" + draw() + "\n\n(Ctrl+C to quit; the run continues)\n")
            sys.stdout.flush()
            time.sleep(a.interval)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
