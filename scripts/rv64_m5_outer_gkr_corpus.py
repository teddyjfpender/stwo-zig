#!/usr/bin/env python3
"""Fresh-receiver tamper corpus for the outer LogUp-GKR section (profile outer_gkr_om31_strict_v1).

Every case runs `rv64-outer-gkr-tool verify` in a NEW process (no cache, no shared state) on a
mutated section file and requires rejection (exit 2); the honest sections must be accepted (exit 0).
The exhaustive in-process sweep (every single word of a test-small section) is the Zig test
"outer GKR tamper corpus"; this corpus covers the named cases end to end, including a GPU-produced
production-shape leaf section.

usage: rv64_m5_outer_gkr_corpus.py --tool BIN --workdir DIR --out JSON [--gpu-leaf FILE --gpu-leaf-seed N]
"""
import argparse
import json
import struct
import subprocess
import time
from pathlib import Path

P = 0x7FFFFFFF
SMALL_VARS = [7, 6, 7, 5, 10, 9, 7, 8]  # profile.zig TEST_SMALL, class order
LEAF_VARS = [23, 22, 23, 21, 27, 26, 24, 24]


def layout(vars_):
    """Word offsets of the outer-GKR wire format (section.zig encode)."""
    L = max(vars_)
    off = {"salt": 5, "roots": 13}
    at = 13 + 16 * len(vars_)
    layers = []
    for depth in range(L):
        rounds = at
        at += 32 * depth
        active = [i for i, v in enumerate(vars_) if v >= L - depth]
        layers.append({"rounds": rounds, "masks": at, "active": active})
        at += 32 * len(active)
    off["layers"] = layers
    off["total"] = at
    return off


def load(path):
    b = Path(path).read_bytes()
    return list(struct.unpack(f"<{len(b) // 4}I", b))


def save(path, words):
    Path(path).write_bytes(struct.pack(f"<{len(words)}I", *words))


def verify(tool, path, extra):
    t = time.monotonic()
    p = subprocess.run([tool, "verify", str(path), *extra], capture_output=True, text=True)
    line = (p.stdout.strip().splitlines() or ["{}"])[-1]
    try:
        out = json.loads(line)
    except json.JSONDecodeError:
        out = {"raw": line}
    return p.returncode, out, time.monotonic() - t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True)
    ap.add_argument("--workdir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--gpu-leaf")
    ap.add_argument("--gpu-leaf-seed", default="0x24628607")
    a = ap.parse_args()
    a.workdir.mkdir(parents=True, exist_ok=True)
    honest = a.workdir / "small-honest.bin"
    unbalanced = a.workdir / "small-unbalanced.bin"
    subprocess.run([a.tool, "prove-cpu", "test-small", "4242", "1", str(honest)], check=True, capture_output=True)
    subprocess.run([a.tool, "prove-cpu", "test-small", "4243", "0", str(unbalanced)], check=True, capture_output=True)
    words = load(honest)
    lay = layout(SMALL_VARS)
    assert lay["total"] == len(words), (lay["total"], len(words))
    good = ["--inputs-seed", "4242", "--balanced"]
    L = lay["layers"]

    def bump(i):
        return lambda w: w.__setitem__(i, (w[i] + 1) % P)

    def setw(i, v):
        return lambda w: w.__setitem__(i, v)

    def zero_root_d(inst):
        def f(w):
            base = lay["roots"] + 16 * inst + 8
            for k in range(8):
                w[base + k] = 0
        return f

    def swap_roots(i, j):
        def f(w):
            ai, aj = lay["roots"] + 16 * i, lay["roots"] + 16 * j
            w[ai:ai + 16], w[aj:aj + 16] = w[aj:aj + 16], w[ai:ai + 16]
        return f

    def leading_zero(depth, rnd):
        def f(w):
            base = L[depth]["rounds"] + 32 * rnd + 24
            for k in range(8):
                w[base + k] = 0
        return f

    cases = [
        ("G01", "header magic", setw(0, 0x524B474E), good),
        ("G02", "header version", setw(1, 2), good),
        ("G03", "class id of another class (leaf)", setw(2, 16), good),
        ("G04", "instance count", setw(3, 7), good),
        ("G05", "layer count", setw(4, 9), good),
        ("G06", "salt (transcript nonce) changed", bump(lay["salt"]), good),
        ("G07", "root numerator, instance 0", bump(lay["roots"]), good),
        ("G08", "root denominator, instance 3", bump(lay["roots"] + 16 * 3 + 8), good),
        ("G09", "root denominator set to zero (pole), instance 0", zero_root_d(0), good),
        ("M01a", "round coefficient: layer 1 round 0 c0", bump(L[1]["rounds"]), good),
        ("M01b", "round coefficient: last layer, last round, c2", bump(L[-1]["rounds"] + 32 * (len(L) - 2) + 16), good),
        ("M01c", "round coefficient: middle layer, coordinate 7", bump(L[5]["rounds"] + 32 * 2 + 7), good),
        ("G10", "round leading coefficient zeroed (degree-3 shape)", leading_zero(4, 1), good),
        ("G11", "mask value, first layer", bump(L[0]["masks"]), good),
        ("G12", "mask value, last layer, last active instance", bump(L[-1]["masks"] + 32 * (len(L[-1]["active"]) - 1) + 31), good),
        ("G13", "instance order: roots of instances 0 and 2 swapped", swap_roots(0, 2), good),
        ("G14", "non-canonical coefficient word (= p)", setw(L[3]["rounds"], P), good),
        ("G15", "truncated section", lambda w: w.pop(), good),
        ("G16", "appended word", lambda w: w.append(0), good),
    ]
    results = []
    rc, out, dt = verify(a.tool, honest, good)
    results.append({"case": "H01", "what": "honest test-small section (closure + terminal)", "expect": "accept", "rc": rc, "out": out, "wall_s": round(dt, 3), "pass": rc == 0})
    for cid, what, mutate, extra in cases:
        w = list(words)
        mutate(w)
        path = a.workdir / f"{cid}.bin"
        save(path, w)
        rc, out, dt = verify(a.tool, path, extra)
        results.append({"case": cid, "what": what, "expect": "reject", "rc": rc, "out": out, "wall_s": round(dt, 3), "pass": rc == 2})
    # M02: the authenticated input evaluations (here: regenerated from a different input seed) differ.
    rc, out, dt = verify(a.tool, honest, ["--inputs-seed", "4243", "--balanced"])
    results.append({"case": "M02", "what": "terminal claims vs different authenticated inputs", "expect": "reject", "rc": rc, "out": out, "wall_s": round(dt, 3), "pass": rc == 2})
    rc, out, dt = verify(a.tool, unbalanced, ["--inputs-seed", "4243"])
    results.append({"case": "G17", "what": "unbalanced LogUp sum with no external term (closure)", "expect": "reject", "rc": rc, "out": out, "wall_s": round(dt, 3), "pass": rc == 2})
    if a.gpu_leaf:
        lw = load(a.gpu_leaf)
        ll = layout(LEAF_VARS)
        assert ll["total"] == len(lw)
        rc, out, dt = verify(a.tool, a.gpu_leaf, ["--no-closure", "--no-terminal"])
        results.append({"case": "H02", "what": "honest GPU-proved leaf-cpu-24628607 section (transcript, strict draws, shape)", "expect": "accept", "rc": rc, "out": out, "wall_s": round(dt, 3), "pass": rc == 0})
        for cid, what, idx in [("M01L", "GPU leaf: round coefficient layer 20 round 7", ll["layers"][20]["rounds"] + 32 * 7 + 3),
                               ("G11L", "GPU leaf: mask value layer 26", ll["layers"][26]["masks"] + 5),
                               ("G07L", "GPU leaf: root of blake lane group 0", ll["roots"] + 16 * 4)]:
            w = list(lw)
            w[idx] = (w[idx] + 1) % P
            path = a.workdir / f"{cid}.bin"
            save(path, w)
            rc, out, dt = verify(a.tool, path, ["--no-closure", "--no-terminal"])
            results.append({"case": cid, "what": what, "expect": "reject", "rc": rc, "out": out, "wall_s": round(dt, 3), "pass": rc == 2})
    summary = {"schema": "rv64-m5-outer-gkr-corpus/v1", "profile": "outer_gkr_om31_strict_v1", "fresh_process_per_case": True,
               "cases": len(results), "passed": sum(r["pass"] for r in results), "results": results}
    a.out.write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: summary[k] for k in ("cases", "passed")}))
    for r in results:
        print(f'{r["case"]:5} {"PASS" if r["pass"] else "FAIL"} rc={r["rc"]} {r["out"].get("error", "accepted" if r["rc"] == 0 else "")} :: {r["what"]}')
    raise SystemExit(0 if summary["passed"] == summary["cases"] else 1)


if __name__ == "__main__":
    main()
