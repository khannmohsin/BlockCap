#!/usr/bin/env python3
"""Mutation testing of models/blockcap_system_model_fixed.als.

Each mutant breaks exactly one rule of the fixed model. For each mutant, the
checks that should detect the break are run. A check that finds a
counterexample (SAT) KILLS the mutant, which is the desired outcome. A mutant
that no targeted check kills SURVIVES, which means the checks do not
constrain that rule.

Usage: tools/mutation_test.py [--final] [--jobs N] [--timeout SECONDS] [--only ID ...]
Writes results_mutation/<mutant>/ and results_mutation/summary.txt.
"""
import argparse
import concurrent.futures as cf
import pathlib
import re
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = ROOT / "models" / "blockcap_system_model_fixed.als"   # override with --base
JAR = ROOT / "tools" / "org.alloytools.alloy.dist.jar"
OUT = ROOT / "results_mutation"                              # override with --out
SCOPE = "for 4 Node, 2 Policy, 3 Slot, 2 Op, 1 Role, 2 Principal, 1 Res, 4 Int, 1..5 steps"

# Original mutant set, for models/blockcap_system_model_fixed.als.
# (id, description, exact text to replace, replacement, checks expected to kill)
MUTANTS_FIXED = [
    ("M01_no_single_slot", "Remove the one-slot-per-(pair, policy) fact (Assumption as:slot)",
     "fact singleSlot {", "pred singleSlot_disabled {", ["P1_TokenUniqueness"]),
    ("M02_reissue_may_widen", "Drop FIX 2: re-issue in place may widen ops",
     "    s.tops' in s.tops                  -- FIX 2 (finding B): may only narrow\n", "",
     ["F2_ReissueNeverWidens"]),
    ("M03_delegate_ops_unbounded", "Delegation: drop ops' subset of p.ops",
     "    ch.tops' in p.tops                -- ops' subset of p.ops\n", "", ["P2_AtDerivation"]),
    ("M04_delegate_outlives_parent", "Delegation: drop t'_exp <= p.t_exp",
     "  Clock.now < t\n  t <= p.texp\n", "  Clock.now < t\n", ["P2_AtDerivation", "P2_EvaluatedChain"]),
    ("M05_delegate_depth_not_reduced", "Delegation: child depth = parent depth (no decrement)",
     "    ch.depth' = p.depth.minus[1]      -- p'.delta = p.delta - 1\n", "    ch.depth' = p.depth\n",
     ["P2_AtDerivation"]),
    ("M06_walk_ignores_ancestor_ops", "Ancestor walk: drop 'op in a.tops'",
     "      Clock.now <= a.texp\n      x.pgen = a.gen\n      op in a.tops\n",
     "      Clock.now <= a.texp\n      x.pgen = a.gen\n", ["P3_AuthCorrectness_Fixed"]),
    ("M07_walk_ignores_revocation", "Ancestor walk: drop 'a not in Rev'",
     "      a in Iss\n      a not in Rev\n      Clock.now <= a.texp\n",
     "      a in Iss\n      Clock.now <= a.texp\n", ["R_RevocationReachesDescendants_Fixed"]),
    ("M08_walk_ignores_generation", "Ancestor walk: drop the generation match",
     "      Clock.now <= a.texp\n      x.pgen = a.gen\n", "      Clock.now <= a.texp\n",
     ["R_ReissueDoesNotRevalidateStaleChild_Fixed", "R_ReissueOutcome_Fixed"]),
    ("M09_walk_ignores_expiry", "Ancestor walk: drop the ancestor expiry check",
     "      a not in Rev\n      Clock.now <= a.texp\n", "      a not in Rev\n", ["P2_EvaluatedChain"]),
    ("M10_fresh_issue_keeps_generation", "Fresh issue does not bump the generation counter",
     "    no s.parent'\n    s.gen' = s.gen.plus[1]\n", "    no s.parent'\n    s.gen' = s.gen\n",
     ["R_ReissueDoesNotRevalidateStaleChild_Fixed", "R_ReissueOutcome_Fixed"]),
    ("M11_auth_uses_eq_as_written", "Undo FIX 1: authFixed without the ancestor walk",
     "    valid[s] and op in s.tops and op in s.pol.pops and ancestorsOK[s, op]\n}\npred authWalk",
     "    valid[s] and op in s.tops and op in s.pol.pops\n}\npred authWalk", ["P3_AuthCorrectness_Fixed"]),
]

# Mutant set for the frozen final model, models/blockcap_final.als.
SCOPE_FINAL = "for 4 Node, 2 Policy, 3 Slot, 2 Op, 2 Role, 2 Res, 2 Principal, 4 Int, 1..5 steps"
MUTANTS_FINAL = [
    ("M01_no_single_slot", "Remove the one-slot-per-(pair, policy) fact (Assumption as:slot)",
     "fact singleSlot {", "pred singleSlot_disabled {", ["P1_TokenUniqueness"]),
    ("M02_reissue_may_widen", "Drop FIX 2: re-issue in place may widen ops",
     "    s.tops' in s.tops                  -- FIX 2 (finding B): may only narrow\n", "",
     ["F2_OpsNeverGrowWithinGeneration"]),
    ("M03_delegate_ops_unbounded", "Delegation: drop ops' subset of p.ops",
     "    ch.tops' in p.tops                -- ops' subset of p.ops\n", "", ["P2_AtDerivation"]),
    ("M04_delegate_outlives_parent", "Delegation: drop t'_exp <= p.t_exp",
     "  Clock.now < t\n  t <= p.texp\n", "  Clock.now < t\n", ["P2_AtDerivation", "P2_EvaluatedChain"]),
    ("M05_delegate_depth_not_reduced", "Delegation: child depth = parent depth (no decrement)",
     "    ch.depth' = p.depth.minus[1]      -- p'.delta = p.delta - 1\n", "    ch.depth' = p.depth\n",
     ["P2_AtDerivation"]),
    ("M06_walk_ignores_ancestor_ops", "Ancestor walk: drop 'op in a.tops'",
     "      Clock.now <= a.texp\n      x.pgen = a.gen\n      op in a.tops\n",
     "      Clock.now <= a.texp\n      x.pgen = a.gen\n", ["P3_AuthCorrectness"]),
    ("M07_walk_ignores_revocation", "Ancestor walk: drop 'a not in Rev'",
     "      a in Iss\n      a not in Rev\n      Clock.now <= a.texp\n",
     "      a in Iss\n      Clock.now <= a.texp\n", ["R_Revocation"]),
    ("M08_walk_ignores_generation", "Ancestor walk: drop the generation match",
     "      Clock.now <= a.texp\n      x.pgen = a.gen\n", "      Clock.now <= a.texp\n",
     ["R_ReissueOutcome"]),
    ("M09_walk_ignores_expiry", "Ancestor walk: drop the ancestor expiry check (expected equivalent)",
     "      a not in Rev\n      Clock.now <= a.texp\n", "      a not in Rev\n", ["P2_EvaluatedChain"]),
    ("M10_fresh_issue_keeps_generation", "Fresh issue does not bump the generation counter",
     "    no s.parent'\n    s.gen' = s.gen.plus[1]\n", "    no s.parent'\n    s.gen' = s.gen\n",
     ["R_ReissueOutcome"]),
    ("M11_auth_uses_eq_as_written", "Undo FIX 1: authFixed without the ancestor walk",
     "    valid[s] and op in s.tops and op in s.pol.pops and ancestorsOK[s, op]\n}\n\n-- ----",
     "    valid[s] and op in s.tops and op in s.pol.pops\n}\n\n-- ----", ["P3_AuthCorrectness"]),
    ("M12_issue_without_owner_check", "issueGrant: drop the caller = own(n_j) guard",
     "  -- guards\n  c = s.obj.own\n", "  -- guards\n", ["A1_NonDelegationChangesOnlyByObjectOwner"]),
    ("M13_revoke_without_owner_check", "revokeGrant: drop the caller = own(n_j) guard",
     "  Ev.actor = c and Ev.kind = RevokeK and Ev.target = s and no Ev.src\n  c = s.obj.own\n",
     "  Ev.actor = c and Ev.kind = RevokeK and Ev.target = s and no Ev.src\n",
     ["A3_RevocationOnlyByObjectOwner"]),
    ("M14_delegate_without_holder_check", "delegateGrant: drop the caller = holder guard",
     "  c = p.sub.own                      -- invoked by the holder of p\n", "",
     ["A2_DelegationOnlyByParentHolder"]),
    ("M15_issue_without_role_match", "issueGrant: drop the role-match guard",
     "  s.sub.role = s.pol.fromRole\n  s.obj.role = s.pol.toRole\n", "",
     ["R1_RootTokensMatchPolicyRoles"]),
]
MUTANTS = MUTANTS_FIXED


def build(mid, old, new, checks):
    src = BASE.read_text()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: anchor found {src.count(old)} times")
    src = src.replace(old, new)
    # Drop every existing command; keep definitions only.
    marker = "run Reach_DelegationChainDepth2 {"
    if marker in src:  # strip the model's own commands
        src = src[:src.index(marker)]
    src = src.rstrip() + "\n\n" + "".join(f"check {c}\n  {SCOPE}\n" for c in checks)
    d = OUT / mid
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{mid}.als"
    f.write_text(src)
    return f


def run(mid, model, idx, check, timeout):
    out = model.parent / f"cmd_{idx}"
    t0 = time.time()
    try:
        p = subprocess.run(
            ["java", "-jar", str(JAR), "exec", "-n", "-q", "-f", "-c", str(idx),
             "-o", str(out), "-t", "json", str(model)],
            capture_output=True, text=True, timeout=timeout)
        secs = int(time.time() - t0)
        if p.returncode != 0:
            return mid, check, "ERROR", secs, (p.stdout + p.stderr)[-400:]
        sat = any(out.glob("*-solution-0.json"))
        return mid, check, "KILLED" if sat else "survived", secs, ""
    except subprocess.TimeoutExpired:
        return mid, check, "TIMEOUT", timeout, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--only", nargs="*", help="mutant ids to run (default: all)")
    ap.add_argument("--final", action="store_true",
                    help="use models/blockcap_final.als, its mutant set and scope")
    ap.add_argument("--out", help="output directory (relative to the model folder)")
    a = ap.parse_args()
    global BASE, OUT, SCOPE, MUTANTS
    if a.final:
        BASE, SCOPE, MUTANTS = ROOT / "models" / "blockcap_final.als", SCOPE_FINAL, MUTANTS_FINAL
        OUT = ROOT / "results_final" / "mutation"
    if a.out:
        OUT = ROOT / a.out
    OUT.mkdir(parents=True, exist_ok=True)
    jobs = []
    for mid, desc, old, new, checks in MUTANTS:
        if a.only and mid not in a.only:
            continue
        model = build(mid, old, new, checks)
        for i, c in enumerate(checks):
            jobs.append((mid, model, i, c))
    results = []
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        futs = [ex.submit(run, m, mod, i, c, a.timeout) for m, mod, i, c in jobs]
        for fu in cf.as_completed(futs):
            r = fu.result()
            results.append(r)
            print(f"{r[2]:8} {r[3]:5}s  {r[0]:34} {r[1]}", flush=True)
    desc = {m[0]: m[1] for m in MUTANTS}
    lines = [f"Base model: {BASE.relative_to(ROOT)}", f"Scope: {SCOPE}", ""]
    for mid in desc:
        if a.only and mid not in a.only:
            continue
        rs = [r for r in results if r[0] == mid]
        verdict = "KILLED" if any(r[2] == "KILLED" for r in rs) else "SURVIVED"
        lines.append(f"{verdict:8} {mid}: {desc[mid]}")
        for r in sorted(rs, key=lambda r: r[1]):
            lines.append(f"           {r[2]:8} {r[3]:5}s  {r[1]}" + (f"  {r[4]}" if r[4] else ""))
    (OUT / ("summary.txt" if not a.only else "summary_rerun.txt")).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
