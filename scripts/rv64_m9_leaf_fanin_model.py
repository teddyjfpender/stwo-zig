#!/usr/bin/env python3
"""M9 fewer-leaves: padding-aware cost model of the OM31 recursion tree, and the leaf fan-in planner mirror.

CPU only. No GPU, no service, no proof. Every input is a committed receipt (cited inline); every output is labelled
[M] measured, [D] derived from measured, or [E] estimate.

Model (all derivations checked against receipts by `self_check()`):
  * A recursion node verifies an ordered list of children. Its raw rows per variable component
    (eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate) are the SUM of its children's verification rows. For folds this
    holds to <0.2% with zero intercept on every fold of the two M7 D2 receipts [D]; for a k-proof leaf it is the
    same rule applied to native children [E, by the identical verifier code path].
  * Padded cells = sum_i width_i * 2^ceil(log2 raw_i) + the fixed lookup tables (87.6 M cells) [D, component_facts widths].
  * Verifying a recursion proof as a fold child costs rows that depend only on the child's largest padded log [D].
  * Kernel GPU-s per node = r_k * cells; node wall = t0 + r_w * cells; both fitted on bench15 [D].

  python3 scripts/rv64_m9_leaf_fanin_model.py --out vectors/reports/rv64-m9-prep/m9-fewer-leaves/model.json
"""
import argparse
import json
import math
from pathlib import Path

# scripts/rv64_m6_diet_receipt.py (component_list.zig component_facts): MAIN + 2x-QM31 INTER + gate preprocessed per row.
COMPONENTS = ["eq", "qm31_ops", "triple_xor", "m_31_to_u_32", "blake_g_gate"]
WIDTH = [4 + 8, 12 + 16, 20 + 48 + 5, 4 + 24 + 3, 52 + 104 + 11]  # 12, 28, 73, 31, 167 cells per padded row
# Fixed tables, identical on every node: xor8 2^16, xor12 2^20, xor4 2^8, xor7 2^14, xor9 2^18, rc16 2^16.
FIXED_CELLS = (2 + 8) * 2**16 + (16 + 64) * 2**20 + (1 + 8) * 2**8 + (1 + 8) * 2**14 + (1 + 8) * 2**18 + (1 + 8) * 2**16

SRC_D2 = "vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package/{24628607,26235156}-combined-d2-coalesce-v1/producer.stderr RECURSION_NODE_SHAPE raw=[...]"
# Native verification rows per proof class [M, raw rows of single-proof leaves in SRC_D2].
NATIVE = {
    # max over the 10 full CPU leaves of both blocks (D2 b4 q54 p20): the planner must not under-predict.
    "cpu": [179654, 5533212, 337632, 875134, 3376320],
    "cpu_mean": [170181, 5188772, 322346, 833610, 3223464],
    "cpu_tail": [139759, 3236107, 201144, 551210, 2011440],  # 24628607 node 7, the short last segment
    "t_a": [7000, 4085155, 228312, 438836, 2283120],  # 3 per block in both receipts
    "t_b": [5012, 3252622, 273632, 536616, 2736320],
    "t_c": [5012, 2575364, 226520, 442500, 2265200],
    "t_d": [4430, 3668414, 278680, 546466, 2786800],
    "t_s": [4234, 790279, 80000, 150016, 800000],
}
# Fold child verification rows by the child's largest padded log [D: fold4 /4, root3 /3, fold17 - L22 child; exact to 0.2%].
CHILD = {
    20: [12874, 1554863, 168190, 308160, 1681900],
    22: [14145, 1674037, 186346, 344464, 1863460],
    23: [14261, 1750349, 194178, 358416, 1941780],
}
CHILD[21] = [(a + b) // 2 for a, b in zip(CHILD[20], CHILD[22])]  # [E] interpolated
CHILD[24] = [c + (c - b) for b, c in zip(CHILD[22], CHILD[23])]  # [E] +1 log extrapolated (one more FRI layer/path level)
CHILD[19] = CHILD[20]  # [E] floor

# Basket: CPU segments and M3 truth proofs [M, vectors/reports/rv64-m3-20261104/summary.json]; bench15 status, native
# window and recursion-after-native [M, codex/rv64-m8-gpu vectors/reports/rv64-m8-20261106/bench15/summary.json+SUMMARY.md].
BASKET = [
    # block, Minstr, gas M, cpu_segments, m3_truths, bench15 (native_window_s, recursion_after_native_s, kernel_gpu_s) or None
    (26235156, 15.31, 5.44, 4, 7, (2.84, 4.84, 6.56)),
    (24647140, 24.60, 7.70, 6, 9, (3.83, 5.38, 8.47)),
    (24628607, 26.89, 7.37, 7, 10, (3.81, 5.69, 8.43)),
    (25229957, 27.08, 9.77, 7, 10, (4.05, 6.18, 9.12)),
    (24628608, 38.60, 12.91, 10, 10, (6.87, 7.27, 11.72)),
    (24626900, 49.12, 16.34, 12, 8, None),
    (24697070, 57.79, 17.44, 14, 17, (11.19, 10.06, 18.39)),
    (24697073, 60.39, 22.28, 15, 13, None),
    (26235168, 113.38, 29.14, 28, 21, None),
    (25229955, 122.48, 39.10, 30, 19, None),
    (24628590, 157.62, 49.13, 38, 18, None),
    (25229951, 165.91, 57.94, 40, 18, None),
    (24628595, 172.80, 54.23, 42, 24, None),
    (24628611, 187.66, 58.86, 45, 22, None),
    (26235159, 204.83, 57.73, 49, 26, None),
]
FOCUS = (24628607, 26235168, 26235159)


def truth_roster(m3_truths):
    """Coalesced D2 roster: 7 family proofs (t_a x3, t_b, t_c, t_d, t_s) [M on 24628607/26235156]. Blocks whose families
    overflow the per-family capacity (bench15 refusals) get the excess as extra full t_a-class proofs after the 3 t_a
    (split families, round-3 p-truth-split) [E: count = max(7, m3_truths - 3), the reduction coalescing gave 24628607]."""
    extra = max(0, m3_truths - 3 - 7)
    return ["t_a"] * (3 + extra) + ["t_b", "t_c", "t_d", "t_s"]


def natives(block):
    b = next(r for r in BASKET if r[0] == block)
    seg = b[3]
    # Short last segment when instructions do not fill whole segments: 26235156 has none [M], 24628607 one [M].
    full = seg if block == 26235156 else seg - 1
    cpu = ["cpu"] * full + ["cpu_tail"] * (seg - full)
    return cpu + truth_roster(b[4])


def plog(n):
    return 0 if n <= 1 else math.ceil(math.log2(n))


def shape(rows):
    return [plog(r) for r in rows]


def cells(rows):
    return sum(w * (1 << plog(r)) for w, r in zip(WIDTH, rows)) + FIXED_CELLS


def unpadded(rows):
    return sum(w * r for w, r in zip(WIDTH, rows))


def add(a, b):
    return [x + y for x, y in zip(a, b)]


def max_log(rows):
    return max(shape(rows))


class Node:
    __slots__ = ("kind", "first", "count", "children", "rows", "natives")

    def __init__(self, kind, first, count, children, rows, natives_):
        self.kind, self.first, self.count, self.children, self.rows, self.natives = kind, first, count, children, rows, natives_

    @property
    def cells(self):
        return cells(self.rows)

    @property
    def log(self):
        return max_log(self.rows)


# Policy caps per component (eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate). "env23" = today's fold envelope on every
# component (fits today, no memory work needed). "blake23" = blake_g_gate (77% of node cells) held at today's fold
# envelope 2^23 while the cheap components may reach 2^24; plus a whole-node cell cap.
CAPS = {"env23": [23, 23, 23, 23, 23], "blake23": [24, 24, 24, 24, 23], "all24": [24, 24, 24, 24, 24]}
NODE_CELL_CAP = 2.2e9  # [E] ~26-27 GB at today's 11.8 B/cell; post-P1 ~13 GB


def fits(rows, cap_log, margin):
    caps = CAPS[cap_log] if isinstance(cap_log, str) else [cap_log] * 5
    padded = [math.ceil(r * (1 + margin)) for r in rows]
    return all(plog(r) <= c for r, c in zip(padded, caps)) and cells(padded) <= NODE_CELL_CAP


def group_leaves(items, kmax, cap_log, margin=0.03, homogeneous=True):
    """Contiguous k-grouping DP [mirror of leaf_fanin.zig groupLeaves]. Minimises sum over groups of padded cells plus
    the unpadded cost of verifying the group's proof in its parent (the fold child surrogate). k = 1 is always allowed
    so the DP is total; a group of >= 2 must fit `cap_log` on every component with `margin` headroom and, when
    `homogeneous`, hold one family kind (CPU or truth) so the leaf class set stays small."""
    n = len(items)
    inf = float("inf")
    best = [0.0] + [inf] * n
    choice = [0] * (n + 1)
    for end in range(1, n + 1):
        rows = [0] * 5
        for k in range(1, min(kmax, end) + 1):
            item = items[end - k]
            rows = add(rows, NATIVE[item])
            if k >= 2:
                if homogeneous == "class" and item != items[end - 1]:
                    break
                if homogeneous and (item.startswith("cpu") != items[end - 1].startswith("cpu")):
                    break
                if not fits(rows, cap_log, margin):
                    break
            cost = best[end - k] + cells(rows) + unpadded(CHILD[min(24, max(19, max_log(rows)))])
            if cost < best[end] - 1e-6:  # strict: ties keep the smaller group (deterministic)
                best[end], choice[end] = cost, k
    groups, end = [], n
    while end:
        groups.append((end - choice[end], choice[end]))
        end -= choice[end]
    return groups[::-1]


def carry_tree(leaves, arity):
    """Port of ready_dag.Plan.initArity (streaming k-ary carry, right finalization) over leaf Nodes."""
    nodes = list()

    def parent(group):
        kids = [nodes[g] for g in group]
        rows = [0] * 5
        for kid in kids:
            rows = add(rows, CHILD[min(24, max(19, kid.log))])
        node = Node("fold", kids[0].first, sum(k.count for k in kids), list(group), rows,
                    sum(k.natives for k in kids))
        nodes.append(node)
        return len(nodes) - 1

    stack = [[None] * arity for _ in range(12)]
    depth = [0] * 12
    for leaf in leaves:
        nodes.append(leaf)
        current = len(nodes) - 1
        level = 0
        while depth[level] + 1 == arity:
            current = parent(stack[level][:arity - 1] + [current])
            depth[level] = 0
            level += 1
        stack[level][depth[level]] = current
        depth[level] += 1
    carry = None
    for level in range(12):
        group = stack[level][:depth[level]] + ([carry] if carry is not None else [])
        if len(group) == 1:
            carry = group[0]
        elif len(group) >= 2:
            carry = parent(group)
    return nodes, carry


def plan(block, kmax=1, cap_log=23, arity=4, homogeneous=True, margin=0.03, truth_only=False):
    items = natives(block)
    if kmax <= 1:
        groups = [(i, 1) for i in range(len(items))]
    elif truth_only:
        n_cpu = sum(1 for i in items if i.startswith("cpu"))
        groups = [(i, 1) for i in range(n_cpu)] + [(n_cpu + f, k) for f, k in
                                                   group_leaves(items[n_cpu:], kmax, cap_log, margin, homogeneous)]
    else:
        groups = group_leaves(items, kmax, cap_log, margin, homogeneous)
    leaves = []
    for ordinal, (first, count) in enumerate(groups):
        rows = [0] * 5
        for item in items[first:first + count]:
            rows = add(rows, NATIVE[item])
        leaves.append(Node("leaf", ordinal, 1, [], rows, count))
    nodes, root = carry_tree(leaves, arity)
    return items, groups, nodes, root


def depths(nodes, root):
    d = [0] * len(nodes)
    for i in range(len(nodes) - 1, -1, -1):
        for c in nodes[i].children:
            d[c] = d[i] + 1
    return d


def node_time(node, t0, rw):
    """Node wall [E]. `rw` is fitted on nodes whose max log is <= 23 only. A node whose largest padded log is 24 also
    doubles the max-log domain work the per-trace-cell fit cannot see (composition polynomial, FRI first layers, OODS
    over the 2^(maxlog+1) domain). Review sensitivity: COMP_TAX_CELLS cells-equivalent per extra log [E, unvalidated]."""
    extra = COMP_TAX_CELLS * ((1 << node.log) - (1 << 23)) / (1 << 23) if node.log > 23 else 0.0
    return t0 + rw * (node.cells + extra)


# OM31 composition = 8 M31 coords x 2 split pieces x 2^maxlog rows [E]: +134 M cells-equivalent going 2^23 -> 2^24.
COMP_TAX_CELLS = 8 * 2 * (1 << 23)


def schedule(nodes, root, gpus, t0, rw, arrivals=None, native_s=None, eager=True):
    """List scheduling, one job per GPU at a time, ready_dag priority (depth*2 + leaf) then id. Returns makespan.

    * `native_s=None`: the after-native window. All natives are done at t = 0 and every GPU is free (bench15
      `recursion after native`, the calibration target).
    * `native_s=[d_i]` (review fix): the JOINT request schedule. Native proof i is a job of d_i seconds on the SAME
      GPUs (one native or one node per GPU at a time, as today's lanes; a node peaks 22-28 GB of a 32 GB card, so a
      node cannot co-reside with a native). A leaf is ready when its last native finishes. `eager=True` lets a ready
      recursion node pre-empt the native queue (streaming); `eager=False` runs every native first (today).
    `arrivals` is the pre-review model (natives land on a fixed clock while recursion runs on all GPUs): it
    double-books the GPUs and is kept only to reproduce the retracted `stream_tail` numbers."""
    d = depths(nodes, root)
    prio = lambda i: d[i] * 2 + (nodes[i].kind == "leaf")
    leaf_natives = {}
    cursor = 0
    for i, n in enumerate(nodes):
        if n.kind == "leaf":
            leaf_natives[i] = (cursor, cursor + n.natives - 1)
            cursor += n.natives
    n_nat = cursor
    nat_done = [None] * n_nat
    if native_s is None:
        nat_done = [0.0 if arrivals is None else arrivals[j] for j in range(n_nat)]
    finish = [None] * len(nodes)
    free = [0.0] * gpus
    pending = set(range(len(nodes)))
    next_native = 0 if native_s is not None else n_nat
    while pending or next_native < n_nat:
        g = min(range(gpus), key=lambda j: free[j])
        now = free[g]
        cands = []
        for i in pending:
            n = nodes[i]
            if n.kind == "leaf":
                last = nat_done[leaf_natives[i][1]]
                if last is not None:
                    cands.append((last, i))
            elif all(finish[c] is not None for c in n.children):
                cands.append((max(finish[c] for c in n.children), i))
        ready_now = [c for c in cands if c[0] <= now + 1e-12]
        run_native = next_native < n_nat and (not eager or not ready_now)
        if run_native:
            nat_done[next_native] = now + native_s[next_native]
            free[g] = nat_done[next_native]
            next_native += 1
            continue
        if ready_now:
            _, i = max(ready_now, key=lambda c: (prio(c[1]), -c[1]))
            start = now
        elif cands:
            t, i = min(cands, key=lambda c: (c[0], -prio(c[1]), c[1]))
            start = t
        else:  # nothing ready on this GPU yet: idle it until the next event
            free[g] = min(x for x in free if x > now) if any(x > now for x in free) else now
            continue
        finish[i] = start + node_time(nodes[i], t0, rw)
        free[g] = finish[i]
        pending.remove(i)
    return finish[root]



# Per-node memory [E]. Today: one node peaks ~22 GB live at fold size (1.866 G cells) [M/D, rv64-m8-engineering-scope.md
# §1 "one recursion node peaks at about 22 GB live"; job-path receipts leaf 22.6 GB / fold 26.6 GB declared,
# rv64-m8-20261106/wire-outer-p2/nodes-24628607.json]. Post-P1 target: <= 11 GB at the same node.
MEM_TODAY_B_PER_CELL = 22e9 / 1.866e9  # 11.8 B/cell
MEM_JOB_FIT = (16.9e9, 5.2)  # bytes = a + b*cells, through leaf (1.097G, 22.6GB) and fold (1.866G, 26.6GB) [D]
MEM_P1_B_PER_CELL = 11e9 / 1.866e9  # 5.9 B/cell
DEVICE_LIMIT = 30064771072  # 28 GiB whole-process gate, GPU_OUTER device_limit_bytes [M]


def mem(c):
    return {"today_prop_gb": round(c * MEM_TODAY_B_PER_CELL / 1e9, 1),
            "today_jobfit_gb": round((MEM_JOB_FIT[0] + MEM_JOB_FIT[1] * c) / 1e9, 1),
            "post_p1_gb": round(c * MEM_P1_B_PER_CELL / 1e9, 1)}


def summarize(block, opts, cal):
    items, groups, nodes, root = plan(block, **opts)
    leaves = [n for n in nodes if n.kind == "leaf"]
    folds = [n for n in nodes if n.kind == "fold"]
    total = sum(n.cells for n in nodes)
    d = depths(nodes, root)
    b = next(r for r in BASKET if r[0] == block)
    out = {
        "natives": len(items), "leaves": len(leaves), "folds": len(folds), "nodes": len(nodes),
        "tree_depth": max(d) if d else 0,
        "groups": [k for _, k in groups],
        "cells_g": round(total / 1e9, 2), "leaf_cells_g": round(sum(n.cells for n in leaves) / 1e9, 2),
        "fold_cells_g": round(sum(n.cells for n in folds) / 1e9, 2),
        "padding_waste": round(1 - sum(unpadded(n.rows) + FIXED_CELLS for n in nodes) / total, 3),
        "max_node_cells_g": round(max(n.cells for n in nodes) / 1e9, 3),
        "max_node_shape": shape(max(nodes, key=lambda n: n.cells).rows),
        "recursion_gpu_s": round(cal["rk"] * total, 2),
    }
    out["max_node_mem"] = mem(max(n.cells for n in nodes))
    out["leaf_classes"] = sorted({"+".join(items[f:f + k]) for f, k in groups})
    for g in (2, 4):
        out[f"window_{g}gpu_s"] = round(schedule(nodes, root, g, cal["t0"], cal["rw"]), 2)
        # Native wall per proof [E]: bench15 2-GPU native window (else the 0.10 s/Minstr 2-GPU fit) x 2 GPU-slots / n.
        w2 = b[5][0] if b[5] else 0.10 * b[1]
        n = len(items)
        native_s = [w2 * 2 / n] * n
        window = w2 * 2 / g
        serial = schedule(nodes, root, g, cal["t0"], cal["rw"], native_s=native_s, eager=False)
        eager = schedule(nodes, root, g, cal["t0"], cal["rw"], native_s=native_s, eager=True)
        out[f"native_window_{g}gpu_s"] = round(window, 2)
        out[f"request_{g}gpu_s"] = round(min(serial, eager), 2)  # native + recursion makespan, shared GPUs [E]
        out[f"request_policy_{g}gpu"] = "eager" if eager < serial else "natives_first"
        out[f"tail_{g}gpu_s"] = round(min(serial, eager) - window, 2)
        # Retracted pre-review number (GPUs double-booked by natives and recursion); kept for the audit trail only.
        arrivals = [window * (i + 1) / n for i in range(n)]
        out[f"retracted_stream_tail_{g}gpu_s"] = round(schedule(nodes, root, g, cal["t0"], cal["rw"], arrivals) - window, 2)
    out["root_chain_nodes"] = critical_chain(nodes, root)
    return out


def critical_chain(nodes, root):
    """Nodes on the path root -> last leaf (the serial tail once the last native lands)."""
    chain, i = [], root
    while True:
        chain.append(i)
        if nodes[i].kind == "leaf":
            return len(chain)
        i = nodes[i].children[-1]


def calibrate():
    """Fit t0, r_w (node wall) on bench15 recursion-after-native (2 GPUs, default one lane, all leaves ready at native
    end), and r_k (kernel ns/cell) with kernel_gpu_s = a*Minstr + r_k*cells, on the 6 proved blocks [D]."""
    proved = [r for r in BASKET if r[5]]
    trees = {r[0]: plan(r[0]) for r in proved}
    best = None
    for t0 in [x / 100 for x in range(0, 61, 1)]:
        for rw in [x / 1000 for x in range(150, 501, 5)]:
            err = 0.0
            for r in proved:
                _, _, nodes, root = trees[r[0]]
                err += (schedule(nodes, root, 2, t0, rw * 1e-9) - r[5][1]) ** 2
            if best is None or err < best[0]:
                best = (err, t0, rw)
    _, t0, rw = best
    # least squares, 2 params, no intercept
    xs = [(r[1], sum(n.cells for n in trees[r[0]][2]) / 1e9, r[5][2]) for r in proved]
    s11 = sum(a * a for a, _, _ in xs); s12 = sum(a * c for a, c, _ in xs); s22 = sum(c * c for _, c, _ in xs)
    y1 = sum(a * y for a, _, y in xs); y2 = sum(c * y for _, c, y in xs)
    det = s11 * s22 - s12 * s12
    a = (y1 * s22 - y2 * s12) / det
    rk = (s11 * y2 - s12 * y1) / det
    resid = []
    for r in proved:
        _, _, nodes, root = trees[r[0]]
        resid.append({"block": r[0], "cells_g": round(sum(n.cells for n in nodes) / 1e9, 2),
                      "measured_rec_s": r[5][1], "model_rec_s": round(schedule(nodes, root, 2, t0, rw * 1e-9), 2),
                      "measured_kernel_gpu_s": r[5][2],
                      "model_kernel_gpu_s": round(a * r[1] + rk * sum(n.cells for n in nodes) / 1e9, 2)})
    return {"t0": t0, "rw": rw * 1e-9, "rk": rk * 1e-9, "native_kernel_gpu_s_per_minstr": a, "fit": resid,
            "label": "D (fit on 6 bench15 blocks; trees are the model's reconstruction, exact on 24628607/26235156)"}


OPTIONS = {
    "baseline": dict(kmax=1, cap_log="env23", arity=4),
    "fold8": dict(kmax=1, cap_log="all24", arity=8),
    "leafk_env23": dict(kmax=4, cap_log="env23", arity=4),
    "leafk_blake23_truth_only": dict(kmax=4, cap_log="blake23", arity=4, truth_only=True),
    "leafk_blake23": dict(kmax=4, cap_log="blake23", arity=4),
    "leafk_blake23_k2": dict(kmax=2, cap_log="blake23", arity=4),
    "leafk_blake23_same": dict(kmax=4, cap_log="blake23", arity=4, homogeneous="class"),
}


def self_check():
    """Reproduce the measured trees and cells of both M7 D2 receipts exactly (node count, structure, padded cells)."""
    exp = {24628607: (19, 21658004224), 26235156: (15, 17844864768)}
    got = {}
    for block, (n_exp, cells_exp) in exp.items():
        items, groups, nodes, root = plan(block)
        total = sum(n.cells for n in nodes)
        got[block] = {"nodes": len(nodes), "cells": total, "receipt_nodes": n_exp, "receipt_cells": cells_exp,
                      "rel_err": round(total / cells_exp - 1, 4)}
        assert len(nodes) == n_exp, (block, len(nodes))
        assert abs(total / cells_exp - 1) < 0.06, (block, total, cells_exp)
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    check = self_check()
    cal = calibrate()
    result = {"schema": "rv64-m9-leaf-fanin-model/v1", "labels": {"M": "measured", "D": "derived", "E": "estimate"},
              "sources": {"rows": SRC_D2, "basket": "vectors/reports/rv64-m3-20261104/summary.json",
                          "bench15": "codex/rv64-m8-gpu vectors/reports/rv64-m8-20261106/bench15/summary.json",
                          "widths": "scripts/rv64_m6_diet_receipt.py (component_list.zig component_facts)"},
              "self_check": check, "calibration": cal, "options": {}, "blocks": {}}
    for name, opts in OPTIONS.items():
        result["options"][name] = opts
    for b in BASKET:
        block = b[0]
        row = {"gas_m": b[2], "minstr": b[1], "cpu_segments": b[3], "natives": len(natives(block))}
        for name, opts in OPTIONS.items():
            row[name] = summarize(block, opts, cal)
        result["blocks"][str(block)] = row
    text = json.dumps(result, indent=1)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")
    print_table(result)


def focus_table(result):
    lines = ["| block | gas | option | natives | leaves | folds | nodes | depth | cells G | rec GPU-s | 2-GPU window s | "
             "4-GPU window s | 2-GPU request s | 4-GPU request s | max node G | max node GB today/post-P1 |", "|" + "---|" * 16]
    for block in FOCUS:
        row = result["blocks"][str(block)]
        for name in OPTIONS:
            s = row[name]
            lines.append(f"| {block} | {row['gas_m']}M | {name} | {s['natives']} | {s['leaves']} | {s['folds']} | {s['nodes']} | "
                         f"{s['tree_depth']} | {s['cells_g']} | {s['recursion_gpu_s']} | {s['window_2gpu_s']} | "
                         f"{s['window_4gpu_s']} | {s['request_2gpu_s']} | {s['request_4gpu_s']} | {s['max_node_cells_g']} | "
                         f"{s['max_node_mem']['today_prop_gb']}/{s['max_node_mem']['post_p1_gb']} |")
    return "\n".join(lines)


def print_table(result):
    cal = result["calibration"]
    print(f"calibration: t0={cal['t0']:.2f}s rw={cal['rw']*1e9:.3f}ns/cell rk={cal['rk']*1e9:.3f}ns/cell "
          f"native={cal['native_kernel_gpu_s_per_minstr']:.3f}GPU-s/Minstr")
    for f in cal["fit"]:
        print("  fit", f)
    print("self-check", result["self_check"])
    print(focus_table(result))
    classes = {name: sorted({c for r in result["blocks"].values() for c in r[name]["leaf_classes"]}) for name in OPTIONS}
    for name, c in classes.items():
        print(f"  leaf classes {name}: {len(c)} {c}")
    for block, row in result["blocks"].items():
        print(f"\n{block} gas={row['gas_m']}M natives={row['natives']}")
        for name in OPTIONS:
            s = row[name]
            print(f"  {name:24s} L={s['leaves']:3d} F={s['folds']:3d} N={s['nodes']:3d} cells={s['cells_g']:7.2f}G "
                  f"gpu={s['recursion_gpu_s']:6.2f}s win2={s['window_2gpu_s']:6.2f} win4={s['window_4gpu_s']:6.2f} "
                  f"req2={s['request_2gpu_s']:6.2f}({s['request_policy_2gpu'][0]}) req4={s['request_4gpu_s']:6.2f}({s['request_policy_4gpu'][0]}) "
                  f"tail2={s['tail_2gpu_s']:5.2f} tail4={s['tail_4gpu_s']:5.2f} old_tail2={s['retracted_stream_tail_2gpu_s']:5.2f} "
                  f"maxnode={s['max_node_cells_g']:.2f}G {s['max_node_mem']} pad={s['padding_waste']} groups={s['groups']}")


if __name__ == "__main__":
    main()
