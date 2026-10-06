#!/usr/bin/env python3
"""Print an Alloy 6 XML trace of blockcap_system_model.als as readable states.

Usage: decode_trace.py <solution.xml>
Only the relations used by the BlockCap model are printed; empty slots
(never issued) are omitted.
"""
import sys
import xml.etree.ElementTree as ET


def atoms(inst, label):
    for s in inst.iter("sig"):
        if s.get("label") == label:
            return [a.get("label") for a in s.iter("atom")]
    return []


def field(inst, name):
    out = {}
    for f in inst.iter("field"):
        if f.get("label") == name:
            for t in f.iter("tuple"):
                a = [x.get("label") for x in t.iter("atom")]
                out.setdefault(a[0], []).append(a[1] if len(a) == 2 else tuple(a[1:]))
    return out


def short(a):
    return a.replace("$", "")


def main(path):
    root = ET.parse(path).getroot()
    insts = root.findall("instance")
    skolems = {}
    for sk in root.iter("skolem"):
        vals = [", ".join(short(x.get("label")) for x in t.iter("atom")) for t in sk.iter("tuple")]
        skolems[sk.get("label")] = vals
    print(f"# {path}")
    if skolems:
        print("Counterexample witnesses:", {k.split("_")[-1]: v for k, v in skolems.items() if v})
    nodes0 = field(insts[0], "role")
    owners = field(insts[0], "own")
    print("Nodes:", ", ".join(f"{short(n)}(role={short(nodes0[n][0])}, own={short(owners[n][0])})"
                              for n in nodes0))
    frm, to = field(insts[0], "fromRole"), field(insts[0], "toRole")
    if frm:
        print("Policy roles:", ", ".join(f"{short(p)}: {short(frm[p][0])}->{short(to[p][0])}" for p in sorted(frm)))
    for idx, inst in enumerate(insts):
        now = field(inst, "now")
        now = list(now.values())[0][0] if now else "?"
        iss, rev, dlg, dep = (set(atoms(inst, f"this/{x}")) for x in ("Iss", "Rev", "Dlg", "Dep"))
        sub, obj, pol = field(inst, "sub"), field(inst, "obj"), field(inst, "pol")
        tops, texp, depth = field(inst, "tops"), field(inst, "texp"), field(inst, "depth")
        parent, gen, pgen = field(inst, "parent"), field(inst, "gen"), field(inst, "pgen")
        pops = field(inst, "pops")
        print(f"\n-- state {idx}  now={now}")
        for p in sorted(pops.keys() | set(atoms(inst, "this/Policy"))):
            print(f"   {short(p)}: ops={{{','.join(short(o) for o in sorted(pops.get(p, [])))}}}"
                  + ("  DEPRECATED" if p in dep else ""))
        for s in sorted(sub):
            if s not in iss and gen.get(s, ["0"])[0] == "0":
                continue
            flags = "".join(["I" if s in iss else "-", "R" if s in rev else "-", "D" if s in dlg else "-"])
            par = short(parent[s][0]) if s in parent else "none"
            print(f"   {short(s)}: {short(sub[s][0])}->{short(obj[s][0])} pol={short(pol[s][0])} "
                  f"[{flags}] ops={{{','.join(short(o) for o in sorted(tops.get(s, [])))}}} "
                  f"texp={texp[s][0]} depth={depth[s][0]} gen={gen[s][0]} parent={par} pgen={pgen[s][0]}")
    print("\nFlags: I=issued R=revoked D=delegable")


if __name__ == "__main__":
    main(sys.argv[1])
