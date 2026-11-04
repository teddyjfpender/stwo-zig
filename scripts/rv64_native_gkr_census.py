#!/usr/bin/env python3
"""Native committed-interaction census per AIR family (stream native-gkr, M5).

Inputs per block:
  --census  JSON from `rv64-native-gkr-census <bundle.json> <rom_log>` (declaration-only, exact widths from the
            production roster code: cpu_components.Plan, global_cpu.layout, truth shapes / v3 catalogue)
  --stderr  producer.stderr of a real run of the same block (GPU_TRACE_OWNERSHIP tree=2 coefficient words = the
            measured committed INTER cells per native proof)
  --gas     gas used by the block
Output: a JSON receipt with per-family cells, bits/gas, the exact reconciliation of declaration cells against the
measured per-proof INTER words (multiset equality), and the predicted cells under rv64-m5-native-gkr/v1
(design/riscv-proving-stack/rv64-native-gkr.md section 3: every component keeps ONE eq+prefix binding pair (16 M31
columns) and every LogUp fraction, local or global, moves into the batched GKR).
Python 3 standard library only.
"""
import argparse, json, re, sys

FAMILY = {
    # CPU word16 execution and its private chips
    "core.cpu": "cpu_word16_exec", "core.boundary": "cpu_word16_exec", "core.selection": "cpu_word16_exec",
    "core.alu": "cpu_word16_exec", "core.alu_tail": "cpu_word16_exec", "core.binary": "cpu_word16_exec",
    "core.binary_tail": "cpu_word16_exec", "core.shift": "cpu_word16_exec", "core.shift_tail": "cpu_word16_exec",
    "core.jalr": "cpu_word16_exec",
    "core.rom": "rom",
    "core.ls": "memory_ls", "core.ls_tail": "memory_ls", "core.initial": "memory_ls", "core.terminal": "memory_ls",
    "dword.0": "memory_ls", "dword.1": "memory_ls",
    "core.range16": "range_u8_u16_tables", "core.range8": "range_u8_u16_tables", "core.and_table": "range_u8_u16_tables",
    "core.shift_table": "range_u8_u16_tables",
    "core.multiplication": "deleg_mul", "core.division": "deleg_div",
    "bridge.keccak": "deleg_keccak_bridge", "sponge.call": "deleg_keccak_bridge", "sponge.perm": "deleg_keccak_bridge",
    "bridge.add": "deleg_secp_bridge", "bridge.double": "deleg_secp_bridge",
    "bridge.sha256": "deleg_sha256_bridge", "bridge.arith256_mod": "deleg_arith256_bridge",
}


def family_of(name):
    if name in FAMILY:
        return FAMILY[name]
    if name.startswith("bulk."):
        return "bulk_memory_jumpdest"
    if name.startswith("bridge."):
        return "deleg_curve_bridges"
    raise SystemExit(f"unmapped component {name}")


def measured_inter(stderr_path, n_native):
    words = []
    with open(stderr_path) as handle:
        for line in handle:
            m = re.match(r"GPU_TRACE_OWNERSHIP tree=2 coefficient_words=(\d+)", line)
            if m:
                words.append(int(m.group(1)))
    # Native proofs commit INTER before any recursion node; recursion INTER commits come after.
    return words[:n_native], words[n_native:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", required=True)
    ap.add_argument("--stderr", required=True)
    ap.add_argument("--gas", type=int, required=True)
    ap.add_argument("--block", type=int, required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    c = json.load(open(a.census))
    fam = {}
    per_proof = []
    binding_pairs = 0

    def add(f, key, cells):
        fam.setdefault(f, {"main": 0, "binding": 0, "global_ram": 0, "global_kio": 0, "global_wire": 0,
                           "classic_local": 0, "new_inter": 0})
        fam[f][key] += cells

    for i, cpu in enumerate(c["cpus"]):
        total = 0
        for s in cpu["slots"]:
            rows = 1 << s["log"]
            f = family_of(s["name"])
            add(f, "main", rows * s["main_cols"])
            add(f, "binding", rows * s["binding_cols"])
            add(f, "global_ram", rows * s["ram_cols"])
            if s["other_cols"]:
                add(f, "global_" + s["other_relation"], rows * s["other_cols"])
            inter = s["binding_cols"] + s["ram_cols"] + s["other_cols"]
            total += rows * inter
            # v1: one eq+prefix pair per component that has ANY fraction (local or global).
            new = 16 if (s["local_terms"] or s["ram_cols"] or s["other_cols"]) else 0
            add(f, "new_inter", rows * new)
        per_proof.append({"proof": f"cpu-{i}", "inter_cells": total})
    for i, t in enumerate(c["truths"]):
        total = 0
        f = "truth_" + t["family"]
        for p in t["parts"]:
            rows = 1 << p["log"]
            add(f, "main", rows * p["main_cols"])
            add(f, "classic_local", rows * p["local_cols"])
            if p["global_cols"]:
                add(f, "global_" + p["global_relation"], rows * p["global_cols"])
            total += rows * (p["local_cols"] + p["global_cols"])
            add(f, "new_inter", rows * (16 if (p["local_cols"] or p["global_cols"]) else 0))
        per_proof.append({"proof": f"truth-{i}", "family": t["family"], "inter_cells": total})

    n_native = len(per_proof)
    measured, _ = measured_inter(a.stderr, n_native)
    declared = sorted(p["inter_cells"] for p in per_proof)
    reconciled = sorted(measured) == declared
    rows = []
    tot = {"main": 0, "inter": 0, "new_inter": 0}
    for f, v in sorted(fam.items(), key=lambda kv: -(kv[1]["binding"] + kv[1]["global_ram"] + kv[1]["global_kio"] + kv[1]["global_wire"] + kv[1]["classic_local"])):
        inter = v["binding"] + v["global_ram"] + v["global_kio"] + v["global_wire"] + v["classic_local"]
        tot["main"] += v["main"]
        tot["inter"] += inter
        tot["new_inter"] += v["new_inter"]
        rows.append(dict(family=f, **v, inter=inter, saving=inter - v["new_inter"],
                         inter_bits_per_gas=round(inter * 31 / a.gas, 1),
                         new_inter_bits_per_gas=round(v["new_inter"] * 31 / a.gas, 1)))
    out = {
        "schema": "rv64-native-gkr-census-receipt/v1",
        "block": a.block, "gas_used": a.gas,
        "label": "M (declaration cells reconciled exactly against measured GPU_TRACE_OWNERSHIP tree=2 words) / D (v1 prediction)",
        "protocol_today": c["protocol"],
        "native_proofs": n_native,
        "reconciled_with_measured_tree2": reconciled,
        "measured_tree2_words": measured,
        "declared_inter_cells_per_proof": per_proof,
        "families": rows,
        "totals": {
            "main_cells": tot["main"], "inter_cells": tot["inter"], "v1_inter_cells": tot["new_inter"],
            "inter_saving_cells": tot["inter"] - tot["new_inter"],
            "inter_bits_per_gas_own_height": round(tot["inter"] * 31 / a.gas, 1),
            "inter_bits_per_gas_lde_b2": round(tot["inter"] * 62 / a.gas, 1),
            "v1_inter_bits_per_gas_own_height": round(tot["new_inter"] * 31 / a.gas, 1),
            "v1_inter_bits_per_gas_lde_b2": round(tot["new_inter"] * 62 / a.gas, 1),
            "main_plus_inter_cells": tot["main"] + tot["inter"],
            "v1_main_plus_inter_cells": tot["main"] + tot["new_inter"],
        },
    }
    json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps(out["totals"], indent=1))
    print("reconciled:", reconciled)
    if not reconciled:
        print("measured", sorted(measured), "\ndeclared", declared, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
