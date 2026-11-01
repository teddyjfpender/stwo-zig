#!/usr/bin/env python3
"""Hardware-independent committed-work report for RV64 Word16 Ethereum runs.

Run with ``python3 -I scripts/rv64_committed_work_report.py``.

Inputs (either or both):
  --run-dir DIR   physical run directory: cost.json (required), roster.json,
                  report.json, bundle.json, physical-*.stages.json and the
                  STWOPRW1 proof files cpu-N.bin / truth-N.bin.
  --cost FILE     a cost.json-shaped receipt (e.g. the committed
                  vectors/reports/rv64-ls32-qualified-20261101/complete-cost.json)
                  when the run directory is gone. Without proofs the PCS/FRI
                  geometry falls back to the declared production suite and the
                  composition width is an assumption (flagged per proof).

Observations only. Nothing here verifies a proof, grants authority, or
measures time. Every count is either read from an artifact ("measured"),
derived by a stated formula from measured shapes ("derived"), or an explicit
assumption ("assumed"/"estimated"); the JSON carries that provenance.

Accounting conventions (see design/riscv-proving-stack/rv64-committed-work-vs-zisk.md):
  * A cell is one M31 element (31 bits). cost.json "columns" are base M31
    columns per tree; secure QM31 interaction columns are already split into
    4 coordinate columns there (asserted below: every interaction width is a
    multiple of 4 and matches the proof's per-tree column count).
  * Trees: 0 fixed (preprocessed), 1 main, 2 interaction, 3 composition
    (quotient). Composition columns = 4 * 2^split, each of 2^D native rows
    where D = 1 + fold_step * inner_fri_layers + log_last_layer (the FRI
    degree bound, which equals the largest trace column log).
  * "native" = trace/coefficient domain; "LDE" = committed evaluation domain,
    native * 2^log_blowup. The Merkle trees hash LDE values.
  * Merkle leaf compressions use the counter-qualified prefixed-BLAKE2s
    ledger from src/integrations/riscv_cpu/word16_global_execution/services/
    hash_accounting_test.zig and the 2026-10-31 mixed-height receipt:
      nonfinal = sum_g (ceil(cum_g/16) - ceil(prev_g/16)) * 2^(log_g + b)
      final    = 2^(max_log + b)
      parents  = 2^(max_log + b) - 1     (one 64-byte compression each)
    with column groups sorted by ascending height. FRI layers use the same
    hasher with one QM31 (4 words) per leaf (fold_step 1 => no leaf packing).
"""
import argparse
import json
import math
import struct
import sys
from pathlib import Path

M31_BITS = 31
WORDS_PER_BLOCK = 16
TREES = ("fixed", "main", "interaction", "composition")
# Declared production suite: src/frontends/riscv/rv64/air/protocol.zig
# (pow_bits=26, FriConfig.init(log_last_layer=0, log_blowup=1, n_queries=70)),
# fold_step 1 (src/integrations/riscv_cpu/word16_execution/pcs_suite.zig).
DECLARED_SUITE = {"pow_bits": 26, "log_blowup": 1, "log_last_layer": 0,
                  "n_queries": 70, "fold_step": 1}
# CPU proofs: maximum constraint degree 3 => composition log split 1
# (src/core/verifier_types.zig COMPOSITION_LOG_SPLIT) => 2 chunks x 4 coords.
ASSUMED_COMPOSITION_COLUMNS = 8


# ---------------------------------------------------------------- proof wire
def parse_proof(data: bytes) -> dict:
    """Shape-only parse of the STWOPRW1 binary wire (src/interop/proof_wire/mod.zig)."""
    at = 0

    def u32():
        nonlocal at
        if at + 4 > len(data):
            raise ValueError("truncated proof")
        v = struct.unpack_from("<I", data, at)[0]
        at += 4
        return v

    def skip(n):
        nonlocal at
        if at + n > len(data):
            raise ValueError("truncated proof")
        at += n

    if data[:8] != b"STWOPRW1":
        raise ValueError("not a STWOPRW1 proof")
    at = 8
    cfg = {"pow_bits": u32(), "log_blowup": u32(), "log_last_layer": u32(),
           "n_queries": u32(), "fold_step": u32()}
    lifting = u32()
    cfg["lifting_log_size"] = None if lifting == 0xFFFFFFFF else lifting
    n_roots = u32()
    skip(32 * n_roots)
    sampled = []
    for _ in range(u32()):
        cols = []
        for _ in range(u32()):
            n = u32()
            skip(16 * n)
            cols.append(n)
        sampled.append(cols)
    decommit = []
    for _ in range(u32()):
        n = u32()
        skip(32 * n)
        decommit.append(n)
    queried = []
    for _ in range(u32()):
        cols = []
        for _ in range(u32()):
            n = u32()
            skip(4 * n)
            cols.append(n)
        queried.append(cols)
    skip(8)  # proof-of-work nonce

    def layer():
        w = u32()
        skip(16 * w)
        h = u32()
        skip(32 * h)
        skip(32)
        return w, h

    first = layer()
    inner = [layer() for _ in range(u32())]
    last = u32()
    skip(16 * last)
    if at != len(data):
        raise ValueError("trailing bytes in proof")
    return {"config": cfg, "roots": n_roots,
            "tree_columns": [len(t) for t in sampled],
            "sampled_qm31": [sum(t) for t in sampled],
            "queried_m31": [sum(t) for t in queried],
            "queried_per_column": sorted({n for t in queried for n in t}),
            "pcs_hash_witnesses": sum(decommit),
            "fri_witness_qm31": first[0] + sum(w for w, _ in inner),
            "fri_hash_witnesses": first[1] + sum(h for _, h in inner),
            "fri_inner_layers": len(inner), "last_layer_qm31": last,
            "bytes": len(data)}


# ---------------------------------------------------------------- hash model
def leaf_compressions(groups, blowup):
    """groups: {native_log: columns}. Counter-qualified prefixed BLAKE2s ledger."""
    cum = 0
    nonfinal = 0
    for log in sorted(groups):
        prev = cum
        cum += groups[log]
        nonfinal += (math.ceil(cum / WORDS_PER_BLOCK) - math.ceil(prev / WORDS_PER_BLOCK)) << (log + blowup)
    top = max(groups) + blowup
    return {"nonfinal": nonfinal, "final": 1 << top, "parents": (1 << top) - 1}


def self_test():
    """Reproduce the counter-qualified 2026-10-31 mixed-height receipt."""
    cases = [  # (groups, nonfinal, final, parents) from mixed-height-hash-accounting-v1.json
        ({5: 34, 8: 3, 13: 3, 14: 2, 16: 32, 18: 3, 20: 47, 22: 3}, 6553792, 8388608, 8388607),
        ({8: 1, 13: 87, 14: 18, 16: 20, 18: 79, 20: 273, 22: 53}, 72073728, 8388608, 8388607),
        ({5: 8, 8: 8, 13: 200, 14: 12, 16: 60, 18: 96, 20: 252, 22: 40}, 62505024, 8388608, 8388607),
    ]
    for groups, nonfinal, final, parents in cases:
        got = leaf_compressions(groups, 1)
        if (got["nonfinal"], got["final"], got["parents"]) != (nonfinal, final, parents):
            raise AssertionError(f"hash ledger drift: {got}")


def estimated_groups(columns, native_cells, max_log):
    """No roster (truth proofs): bound and estimate leaf work from aggregates.

    Upper bound puts every column at max height (exact in this direction since
    each ceil-delta block is charged at <= 2^max rows). The estimate scales the
    upper bound by native/lifted cell density.
    """
    if columns == 0:
        return None
    upper = {max_log: columns}
    density = native_cells / (columns << max_log)
    return upper, density


# ---------------------------------------------------------------- loading
def load_json(path):
    return json.loads(Path(path).read_text())


def roster_groups(roles, tree):
    groups = {}
    for r in roles:
        if not r.get("present", True):
            continue
        w = r["columns"][tree]
        if w:
            groups[r["log"]] = groups.get(r["log"], 0) + w
    return groups


def analyse(cost, roster, proofs_dir, report):
    blocks = []
    kinds = [("cpu", i, s) for i, s in enumerate(cost["cpu"])] + \
            [("truth", i, s) for i, s in enumerate(cost["truth"])]
    roster_cpu = roster["cpu"] if roster else None
    if roster_cpu is not None and len(roster_cpu) != len(cost["cpu"]):
        raise ValueError("roster/cost CPU count mismatch")
    proofs = []
    for kind, i, shape in kinds:
        entry = {"kind": kind, "index": i, "provenance": {}}
        proof = None
        if proofs_dir is not None:
            p = Path(proofs_dir) / f"{kind}-{i}.bin"
            if p.exists():
                proof = parse_proof(p.read_bytes())
        if proof:
            cfg = proof["config"]
            if proof["roots"] != 4 or len(proof["tree_columns"]) != 4:
                raise ValueError(f"{kind}-{i}: expected 4 PCS trees")
            if proof["tree_columns"][:3] != shape["columns"]:
                raise ValueError(f"{kind}-{i}: proof tree widths {proof['tree_columns'][:3]} != cost {shape['columns']}")
            comp_cols = proof["tree_columns"][3]
            D = 1 + cfg["fold_step"] * proof["fri_inner_layers"] + cfg["log_last_layer"]
            entry["provenance"]["pcs"] = "measured: proof wire"
        else:
            cfg = dict(DECLARED_SUITE)
            comp_cols = ASSUMED_COMPOSITION_COLUMNS
            D = max(shape["max_log"])
            entry["provenance"]["pcs"] = "assumed: declared production suite, composition 8 columns, D = max trace log"
        if D != max(shape["max_log"]):
            raise ValueError(f"{kind}-{i}: FRI degree bound {D} != max trace log {max(shape['max_log'])}")
        if shape["columns"][2] % 4:
            raise ValueError(f"{kind}-{i}: interaction width not a multiple of 4 (QM31 split)")
        b = cfg["log_blowup"]
        cells = list(shape["native_cells"]) + [comp_cols << D]
        cols = list(shape["columns"]) + [comp_cols]
        hashes = {}
        exact = True
        for t in range(3):
            if cols[t] == 0:
                hashes[TREES[t]] = {"nonfinal": 0, "final": 0, "parents": 0}
                continue
            if kind == "cpu" and roster_cpu is not None:
                g = roster_groups(roster_cpu[i], t)
                if sum(g.values()) != cols[t] or sum(c << l for l, c in g.items()) != cells[t]:
                    raise ValueError(f"cpu-{i}: roster histogram disagrees with cost tree {t}")
                hashes[TREES[t]] = leaf_compressions(g, b)
            else:
                exact = False
                upper, density = estimated_groups(cols[t], cells[t], shape["max_log"][t])
                ub = leaf_compressions(upper, b)
                hashes[TREES[t]] = {"nonfinal": round(ub["nonfinal"] * density), "final": ub["final"],
                                    "parents": ub["parents"], "nonfinal_upper_bound": ub["nonfinal"]}
        hashes["composition"] = leaf_compressions({D: comp_cols}, b)
        entry["provenance"]["leaf_histogram"] = "derived: roster.json exact" if exact else \
            "estimated: no per-height histogram; nonfinal = upper bound x native/lifted density"
        # FRI: first layer on the circle domain 2^(D+b), then line layers.
        fri_layers = [D + b] + [D + b - 1 - k * cfg["fold_step"] for k in range(proof["fri_inner_layers"] if proof else D - cfg["log_last_layer"] - 1)]
        fri = {"nonfinal": 0, "final": 0, "parents": 0}
        for log in fri_layers:
            h = leaf_compressions({log - b: 4}, b)  # 4 coordinate words per leaf
            for k in fri:
                fri[k] += h[k]
        entry.update({
            "config": cfg, "fri_degree_log": D, "composition_columns": comp_cols,
            "columns": dict(zip(TREES, cols)),
            "native_cells": dict(zip(TREES, cells)),
            "lde_cells": dict(zip(TREES, [c << b for c in cells])),
            "merkle_compressions": hashes, "fri_merkle_compressions": fri,
            "fri_committed_layers": len(fri_layers),
            "fri_committed_qm31_lde": sum(1 << l for l in fri_layers),
            "pow_expected_hashes": 1 << cfg["pow_bits"],
        })
        if proof:
            entry["openings"] = {k: proof[k] for k in ("sampled_qm31", "queried_m31", "queried_per_column",
                                                       "pcs_hash_witnesses", "fri_witness_qm31",
                                                       "fri_hash_witnesses", "last_layer_qm31")}
            entry["proof_bytes"] = proof["bytes"]
        proofs.append(entry)
    return proofs


def summarise(proofs, instructions, gas):
    out = {"proofs": len(proofs), "cpu_proofs": sum(p["kind"] == "cpu" for p in proofs),
           "truth_proofs": sum(p["kind"] == "truth" for p in proofs)}
    blowups = {p["config"]["log_blowup"] for p in proofs}
    if len(blowups) != 1:
        raise ValueError("mixed blowups")
    b = blowups.pop()
    out["log_blowup"] = b
    native = {t: sum(p["native_cells"][t] for p in proofs) for t in TREES}
    lde = {t: sum(p["lde_cells"][t] for p in proofs) for t in TREES}
    out["native_cells"] = dict(native, total=sum(native.values()),
                               trace_total_excl_composition=native["fixed"] + native["main"] + native["interaction"])
    out["lde_cells"] = dict(lde, total=sum(lde.values()))
    out["native_bits"] = {k: v * M31_BITS for k, v in out["native_cells"].items()}
    out["lde_bits"] = {k: v * M31_BITS for k, v in out["lde_cells"].items()}
    out["witness_lde_bits_excl_fixed"] = (lde["main"] + lde["interaction"] + lde["composition"]) * M31_BITS
    merkle = {}
    for t in TREES:
        merkle[t] = {k: sum(p["merkle_compressions"][t].get(k, 0) for p in proofs) for k in ("nonfinal", "final", "parents")}
    merkle["fri"] = {k: sum(p["fri_merkle_compressions"][k] for p in proofs) for k in ("nonfinal", "final", "parents")}
    for v in merkle.values():
        v["leaf"] = v["nonfinal"] + v["final"]
        v["total"] = v["leaf"] + v["parents"]
    merkle["all"] = {k: sum(merkle[t][k] for t in list(TREES) + ["fri"]) for k in ("leaf", "parents", "total")}
    out["blake2s_compressions"] = merkle
    out["pow_expected_hashes"] = sum(p["pow_expected_hashes"] for p in proofs)
    out["fri_layers_per_proof"] = sorted({p["fri_committed_layers"] for p in proofs})
    out["queries"] = sorted({p["config"]["n_queries"] for p in proofs})
    if all("openings" in p for p in proofs):
        o = {}
        for k in ("sampled_qm31", "queried_m31"):
            o[k] = sum(sum(p["openings"][k]) for p in proofs)
        for k in ("pcs_hash_witnesses", "fri_witness_qm31", "fri_hash_witnesses", "last_layer_qm31"):
            o[k] = sum(p["openings"][k] for p in proofs)
        out["openings"] = o
        out["proof_bytes"] = sum(p["proof_bytes"] for p in proofs)
    out["estimated_proofs"] = [f"{p['kind']}-{p['index']}" for p in proofs
                               if not p["provenance"]["leaf_histogram"].startswith("derived")]
    if instructions:
        out["instructions"] = instructions
        out["per_instruction"] = {
            "native_cells": out["native_cells"]["total"] / instructions,
            "native_bits": out["native_bits"]["total"] / instructions,
            "lde_bits": out["lde_bits"]["total"] / instructions,
            "lde_bits_by_tree": {t: lde[t] * M31_BITS / instructions for t in TREES},
            "blake2s_compressions": merkle["all"]["total"] / instructions,
        }
    if gas:
        out["gas_used"] = gas
        out["per_gas"] = {"native_bits": out["native_bits"]["total"] / gas,
                          "lde_bits": out["lde_bits"]["total"] / gas,
                          "lde_bits_by_tree": {t: lde[t] * M31_BITS / gas for t in TREES}}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir")
    ap.add_argument("--cost", help="cost.json-shaped receipt (used when --run-dir lacks cost.json)")
    ap.add_argument("--instructions", type=int, help="override retired instruction count")
    ap.add_argument("--gas", type=int, help="block gas used, for bits-per-gas")
    ap.add_argument("--label")
    ap.add_argument("--per-proof", action="store_true", help="include per-proof rows")
    ap.add_argument("--expect-native-cells", type=int, help="fail unless the total native cells match")
    args = ap.parse_args(argv)
    self_test()
    run = Path(args.run_dir) if args.run_dir else None
    cost_path = Path(args.cost) if args.cost else (run / "cost.json" if run else None)
    if cost_path is None or not cost_path.exists():
        ap.error("need --run-dir with cost.json or --cost")
    cost = load_json(cost_path)
    roster = load_json(run / "roster.json") if run and (run / "roster.json").exists() else None
    report = load_json(run / "report.json") if run and (run / "report.json").exists() else {}
    proofs = analyse(cost, roster, run, report)
    instructions = args.instructions or sum(a["retirements"] for a in cost.get("active", [])) or report.get("total_steps")
    if report.get("total_steps") and instructions != report["total_steps"] and not args.instructions:
        raise ValueError("cost.json retirements differ from report total_steps")
    summary = summarise(proofs, instructions, args.gas)
    stages = sorted(p.name for p in run.glob("physical-*.stages.json")) if run else []
    if run and stages and stages != [f"physical-{i:04}.stages.json" for i in range(len(proofs))]:
        raise ValueError("stage profiles do not cover exactly one per proof")
    out = {"schema": 1, "label": args.label, "scope": "observations only; no proof verification; no timing",
           "sources": {"cost": str(cost_path), "roster": bool(roster), "report": bool(report),
                       "proof_files": sum(1 for p in proofs if "proof_bytes" in p),
                       "stage_profiles": len(stages)},
           "completed_ethereum_block": report.get("completed_ethereum_block"),
           "core_schema": report.get("core_schema"),
           "summary": summary}
    if args.per_proof:
        out["per_proof"] = proofs
    if args.expect_native_cells is not None and summary["native_cells"]["trace_total_excl_composition"] != args.expect_native_cells:
        raise SystemExit(f"native cells {summary['native_cells']['trace_total_excl_composition']} != expected {args.expect_native_cells}")
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
