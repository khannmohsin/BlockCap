#!/usr/bin/env python3
"""Render an Alloy counterexample trace (XML) as a staged TikZ figure.

Usage: tools/trace_to_tikz.py <solution.xml> <out.tex> [--states 3,4]
       [--subject NodeX --object NodeY --op OpZ]

Used for finding C (Eq. (eq:auth) as originally written). For each selected
state, the delegation chain ending at the counterexample's subject/object
token is drawn left to right (root -> ... -> leaf), with each token's
subject->object pair and operation set. Tokens whose operation set changed
since the previous selected state are highlighted. Below the last panel, the
authorization decision for (subject, op, object) is computed FROM THE TRACE
DATA under both rules:
  - Eq. (eq:auth) as originally written (Gamma + token + policy), and
  - Eq. (eq:auth) with the ancestor conjunct (as in the revised Section II).
Nothing is hand-entered: names, operation sets, links and both decisions
come from the XML. Writes a TikZ picture (no preamble) to <out.tex>.
"""
import argparse
import re
import sys
import xml.etree.ElementTree as ET


def atoms(inst, label):
    for s in inst.iter("sig"):
        if s.get("label") == label:
            return {a.get("label") for a in s.iter("atom")}
    return set()


def field(inst, name):
    out = {}
    for f in inst.iter("field"):
        if f.get("label") == name:
            for t in f.iter("tuple"):
                a = [x.get("label") for x in t.iter("atom")]
                out.setdefault(a[0], []).append(a[1] if len(a) == 2 else tuple(a[1:]))
    return out


def state(inst):
    one = lambda d, k: d.get(k, [None])[0]
    now = int(list(field(inst, "now").values())[0][0])
    slots = {}
    for s, (sub,) in ((k, v) for k, v in field(inst, "sub").items()):
        slots[s] = dict(
            sub=sub, obj=one(field(inst, "obj"), s), pol=one(field(inst, "pol"), s),
            ops=set(field(inst, "tops").get(s, [])), texp=int(one(field(inst, "texp"), s)),
            depth=int(one(field(inst, "depth"), s)), parent=one(field(inst, "parent"), s),
            gen=int(one(field(inst, "gen"), s)), pgen=int(one(field(inst, "pgen"), s)))
    return dict(now=now, slots=slots, pops={p: set(v) for p, v in field(inst, "pops").items()},
                iss=atoms(inst, "this/Iss"), rev=atoms(inst, "this/Rev"), dep=atoms(inst, "this/Dep"))


def valid(st, s):
    t = st["slots"][s]
    return s in st["iss"] and s not in st["rev"] and st["now"] <= t["texp"] and t["pol"] not in st["dep"]


def gamma(st, i, j):
    pair = [s for s, t in st["slots"].items() if t["sub"] == i and t["obj"] == j]
    for d in {st["slots"][s]["pol"] for s in pair}:
        if sum(1 for s in pair if st["slots"][s]["pol"] == d and valid(st, s)) > 1:
            return False
    for s in pair:
        t = st["slots"][s]
        if t["parent"]:
            p = st["slots"][t["parent"]]
            if not (t["ops"] <= p["ops"] and t["texp"] <= p["texp"] and t["depth"] < p["depth"]):
                return False
    return True


def ancestors_ok(st, s, op):
    x, seen = s, set()
    while st["slots"][x]["parent"] and x not in seen:
        seen.add(x)
        a = st["slots"][x]["parent"]
        ta = st["slots"][a]
        if not (a in st["iss"] and a not in st["rev"] and st["now"] <= ta["texp"]
                and st["slots"][x]["pgen"] == ta["gen"] and op in ta["ops"]):
            return False
        x = a
    return True


def auth(st, i, op, j, walk):
    if not gamma(st, i, j):
        return False
    for s, t in st["slots"].items():
        if t["sub"] == i and t["obj"] == j and valid(st, s) and op in t["ops"] \
                and op in st["pops"].get(t["pol"], set()) and (not walk or ancestors_ok(st, s, op)):
            return True
    return False


def chain(st, leaf):
    c = [leaf]
    while st["slots"][c[-1]]["parent"] and st["slots"][c[-1]]["parent"] not in c:
        c.append(st["slots"][c[-1]]["parent"])
    return list(reversed(c))  # root first


def n(a):  # Node3 -> n_3, Op1 -> o_1
    m = re.match(r"([A-Za-z]+)\$?(\d+)", a)
    return {"Node": "n", "Op": "o"}.get(m.group(1), m.group(1)) + "_{" + m.group(2) + "}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xml")
    ap.add_argument("out")
    ap.add_argument("--states", default="")
    ap.add_argument("--subject")
    ap.add_argument("--object")
    ap.add_argument("--op")
    a = ap.parse_args()
    root = ET.parse(a.xml).getroot()
    insts = root.findall("instance")
    sk = {s.get("label").split("_")[-1]: [x.get("label") for x in s.iter("atom")]
          for s in root.iter("skolem")}
    subj = a.subject or sk["i"][0]
    obj = a.object or sk["j"][0]
    op = a.op or sk["op"][0]
    idx = [int(x) for x in a.states.split(",")] if a.states else [len(insts) - 2, len(insts) - 1]
    sts = [state(insts[i]) for i in idx]
    last = sts[-1]
    leaf = [s for s, t in last["slots"].items() if t["sub"] == subj and t["obj"] == obj and valid(last, s)][0]
    names = {}
    ch = chain(last, leaf)
    for k, s in enumerate(ch):
        names[s] = "p_{r}" if k == 0 else ("p_{c}" if k < len(ch) - 1 else "p_{g}") if len(ch) == 3 \
            else f"p_{{{k}}}"
    out = [r"\begin{tikzpicture}[>=stealth, font=\scriptsize,",
           r"  tok/.style={rectangle, draw, rounded corners=2pt, fill=gray!8, align=center, minimum width=1.9cm, inner sep=2pt},",
           r"  hot/.style={tok, draw=red!70!black, fill=red!10, very thick},",
           r"  lab/.style={font=\scriptsize\bfseries, anchor=west}]"]
    y = 0.0
    prev = None
    for k, (i, st) in enumerate(zip(idx, sts)):
        title = ("(%s) state %d: delegation chain" % ("abcdefg"[k], i)) if k == 0 else \
                ("(%s) state %d: object owner narrows $%s$ in place" % ("abcdefg"[k], i,
                 names[[s for s in ch if prev and st["slots"][s]["ops"] != prev["slots"][s]["ops"]][0]])
                 if prev and any(st["slots"][s]["ops"] != prev["slots"][s]["ops"] for s in ch)
                 else "(%s) state %d" % ("abcdefg"[k], i))
        out.append(rf"\node[lab] at (-1.05,{y+0.62:.2f}) {{{title}}};")
        for m, s in enumerate(ch):
            t = st["slots"][s]
            changed = prev is not None and t["ops"] != prev["slots"][s]["ops"]
            ops = ",".join(n(o) for o in sorted(t["ops"])) or r"\emptyset"
            out.append(rf"\node[{'hot' if changed else 'tok'}] (s{k}{m}) at ({m*2.45:.2f},{y:.2f}) "
                       rf"{{${names[s]}$: ${n(t['sub'])}\!\to\!{n(t['obj'])}$\\ $ops=\{{{ops}\}}$}};")
            if m:
                out.append(rf"\draw[->] (s{k}{m}) -- (s{k}{m-1}) node[midway, above] {{$\prec$}};")
        prev = st
        y -= 1.45
    orig, fixed = auth(last, subj, op, obj, False), auth(last, subj, op, obj, True)
    req = rf"$\mathrm{{Auth}}({n(subj)}, {n(op)}, {n(obj)})$"
    out.append(rf"\node[lab] at (-1.05,{y+0.62:.2f}) {{(c) evaluation in state {idx[-1]} of {req}}};")
    out.append(rf"\node[anchor=west, align=left] at (-1.05,{y+0.05:.2f}) {{"
               rf"without ancestor conjunct: \textbf{{{'granted' if orig else 'denied'}}}, "
               rf"although ${n(op)} \notin {names[ch[0]]}.ops$\\"
               rf"with ancestor conjunct (Eq.~\eqref{{eq:auth}}): \textbf{{{'granted' if fixed else 'denied'}}}, "
               rf"since ancestor ${names[ch[0]]}$ lacks ${n(op)}$}};")
    out.append(r"\end{tikzpicture}")
    open(a.out, "w").write("\n".join(out) + "\n")
    print(f"states {idx}; chain {[names[s] for s in ch]}; original={'granted' if orig else 'denied'}, "
          f"revised={'granted' if fixed else 'denied'}", file=sys.stderr)


if __name__ == "__main__":
    main()
