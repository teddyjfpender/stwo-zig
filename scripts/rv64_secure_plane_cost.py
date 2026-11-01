#!/usr/bin/env python3
"""Source/roster geometry model only, never a security or peak-memory certificate."""
import argparse
import hashlib
import json
from pathlib import Path


def run(cost, cpu_split, truth_split, blowup):
    result = {}
    combined = [0, 0, 0]
    combined_lifted = [0, 0, 0]
    composition = 0
    fri_initial_values = 0
    for family, split in (("cpu", cpu_split), ("truth", truth_split)):
        rows = cost[family]
        totals = [0, 0, 0]
        lifted = [0, 0, 0]
        comp = 0
        fri = 0
        for proof in rows:
            if len(proof["native_cells"]) != 3 or len(proof["lifted_leaf_cells"]) != 3:
                raise ValueError("expected fixed/MAIN/INTER triples")
            if proof["columns"][2] % 4:
                raise ValueError("INTER width is not QM31-coordinate aligned")
            for i in range(3):
                for key in ("native_cells", "lifted_leaf_cells"):
                    value = proof[key][i]
                    if type(value) is not int or value < 0:
                        raise ValueError("nonnegative integer cells required")
                totals[i] += proof["native_cells"][i]
                lifted[i] += proof["lifted_leaf_cells"][i]
            mask_log = max(proof["max_log"])
            if not 1 <= mask_log <= 29:
                raise ValueError("unsupported source domain")
            # For this admitted route, max component degree minus split equals
            # the maximum recorded native column height. This is an explicit
            # source-checked geometry condition, not inferred proof authority.
            comp += (4 << split) * (1 << mask_log)
            fri += 1 << (mask_log + blowup)
        combined = [a + b for a, b in zip(combined, totals)]
        combined_lifted = [a + b for a, b in zip(combined_lifted, lifted)]
        composition += comp
        fri_initial_values += fri
        result[family] = {"proofs": len(rows), "fixed_main_inter_cells": totals,
                          "lifted_fixed_main_inter_words_excluding_blowup": lifted,
                          "composition_split": split, "composition_native_cells_qm31": comp,
                          "fri_initial_secure_values": fri}
    fixed, main, interaction = combined
    result["total"] = {
        "fixed_cells_unchanged": fixed,
        "main_cells_unchanged": main,
        "interaction_cells_qm31": interaction,
        "interaction_cells_om31": 2 * interaction,
        "main_inter_qm31": main + interaction,
        "main_inter_om31": main + 2 * interaction,
        "fixed_main_inter_qm31": fixed + main + interaction,
        "fixed_main_inter_om31": fixed + main + 2 * interaction,
        "composition_native_cells_qm31": composition,
        "composition_native_cells_om31": 2 * composition,
        "trace_plus_composition_qm31": fixed + main + interaction + composition,
        "trace_plus_composition_om31": fixed + main + 2 * interaction + 2 * composition,
        "additional_native_interaction_bytes_over_block": 4 * interaction,
        "additional_native_composition_bytes_over_block": 4 * composition,
        "additional_interaction_lde_bytes_over_block": (4 << blowup) * interaction,
        "fri_initial_secure_values": fri_initial_values,
        "fri_initial_payload_bytes_qm31": 16 * fri_initial_values,
        "fri_initial_payload_bytes_om31": 32 * fri_initial_values,
        # Fold1 geometric payload bound; no retained-lifetime or query claim.
        "fri_all_layers_payload_upper_bound_bytes_qm31": 32 * fri_initial_values,
        "fri_all_layers_payload_upper_bound_bytes_om31": 64 * fri_initial_values,
        "lifted_interaction_leaf_words_excluding_blowup_qm31": combined_lifted[2],
        "lifted_interaction_leaf_words_excluding_blowup_om31": 2 * combined_lifted[2],
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cost", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--cpu-split", type=int, choices=(1, 2), required=True)
    parser.add_argument("--truth-split", type=int, choices=(1, 2), required=True)
    args = parser.parse_args()
    raw = args.cost.read_bytes()
    cost = json.loads(raw)
    result = {
        "schema": "rv64-secure-plane-geometry-cost-v1",
        "scope": "Current physical roster bound, not a migrated protocol, security certificate, traffic measurement or peak memory",
        "source_head": args.source_head,
        "source_cost_sha256": hashlib.sha256(raw).hexdigest(),
        "control": {"secure_coordinates": 4, "blowup_log": 1, "fri_fold_step": 1,
                    "cpu_composition_split": args.cpu_split, "truth_composition_split": args.truth_split},
        "candidate_secure_coordinates": 8,
        "whole_protocol_128_certificate": False,
        "retirements": sum(row["retirements"] for row in cost["active"]),
        "assumptions": [
            "All recorded INTER planes are extension-coordinate columns; MAIN multiplicities remain base-field",
            "Keep current independently sized roles, geometry, fold1 and blowup2 for cost isolation only",
            "CPU split1 is word16_execution/components.zig authority; current Keccak/secp truth authorities declare split2",
            "Fixed/MAIN unchanged; composition secure coordinates double separately",
            "FRI initial domain uses maximum recorded native height plus current blowup; total-layer bound is geometric fold1",
            "Per-proof summed cell volumes are not unique retained setup memory, measured memory traffic or peak RSS",
            "A justified128-bit FRI/ROM/recursion profile may require other parameters and additional work",
        ],
    }
    result.update(run(cost, args.cpu_split, args.truth_split, 1))
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
