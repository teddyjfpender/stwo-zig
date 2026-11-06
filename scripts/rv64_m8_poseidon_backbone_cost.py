#!/usr/bin/env python3
"""Net GPU-seconds per block for the Poseidon2 recursion backbone options.

Inputs are committed receipts only: the M8 kernel A/B receipt (measured P2
and Blake retained-tree rates), the M7 exact native hash-operation census
(24628607 warm), the D2+coalescing recursion cell census and after-native
GPU-second partition, and the M7 full CPU-leaf cell censuses. Every output
carries its label: M measured, D derived from measured, E estimate.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
M7 = ROOT / "vectors/reports/rv64-m7-20261105"
D2 = M7 / "d2-composed/combined-d2-package"

# M7 GO-NOGO.md, same five-step JUMPDEST CPU0 leaf at b4/q54/P20/fold4 [M/D].
LEAF_BLAKE_CELLS = 554_830_848
LEAF_PURE_P2_CELLS = 106_332_160
LEAF_MIXED_CELLS = 247_794_688
# D2 + coalescing, 24628607 warm (d2-composed/README.md) [M].
REQUEST_KERNEL_GPU_S = 10.584695335
RECURSION_LOG_BLOWUP = 1  # producer.stderr "blowup=1" on recursion nodes [M]


def rates(kernel_receipt, variant):
    """Permutations/s and hashed cells/s on the widest and a narrow class."""
    out = {}
    for row in kernel_receipt["classes"]:
        if (row["columns"], row["log_rows"]) not in ((479, 20), (128, 20)):
            continue
        cells = row["columns"] << row["log_rows"]
        rows = 1 << row["log_rows"]
        blake_compressions = rows * -(-row["columns"] * 4 // 64) + (rows - 1)
        key = f'{row["columns"]}x2^{row["log_rows"]}'
        p2_s = row[variant]["p2_ms"] / 1e3
        blake_s = row[variant]["blake_ms"] / 1e3
        out[key] = dict(p2_perm_per_s=row["permutations"] / p2_s,
                        p2_cell_ns=p2_s / cells * 1e9,
                        blake_compress_per_s=blake_compressions / blake_s,
                        blake_cell_ns=blake_s / cells * 1e9)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel-receipt", type=Path, required=True)
    p.add_argument("--variant", default="fused")
    p.add_argument("--baseline-variant", default="register")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    kernel = json.loads(a.kernel_receipt.read_text())
    native = json.loads((M7 / "poseidon2/gpu-commit-common-rotate/24628607-native-hash-budget.json")
                        .read_text())["warm_omit_FIXED_commits"]
    cells = json.loads((D2 / "derived-recursive-cells.json").read_text())["runs"][0]
    assert cells["configuration"] == "24628607-combined-d2-coalesce-v1"
    after = json.loads((D2 / "24628607-combined-d2-coalesce-v1/after-native.json").read_text())
    warm = next(r for r in after["requests"] if r["trial"] == 1)
    rec_gpu_s = warm["phase_kernel_gpu_seconds"]  # [M] all after-native kernels
    tc_gpu_s = sum(warm["ranges"][k]["correlated_gpu_activity"]["kernel"]["gpu_seconds"]
                   for k in ("rv64/TC/MAIN", "rv64/TC/INTER", "rv64/TC/FIXED"))
    rec_cells = cells["cells"]["total"]
    ns_per_cell = rec_gpu_s / rec_cells * 1e9  # [D] cell-linear recursion cost

    result = dict(schema="rv64-m8-poseidon-backbone-cost/v1", block=24628607,
                  inputs=dict(kernel_receipt=str(a.kernel_receipt.relative_to(ROOT)),
                              variant=a.variant, baseline_variant=a.baseline_variant),
                  measured=dict(request_kernel_gpu_s=REQUEST_KERNEL_GPU_S,
                                recursion_after_native_kernel_gpu_s=rec_gpu_s,
                                recursion_trace_commit_kernel_gpu_s=tc_gpu_s,
                                recursion_cells=rec_cells, leaf_cells=cells["leaf_cells"],
                                fold_cells=cells["fold_cells"],
                                native_p2_prefix_permutations=native["p2_prefix_permutations"],
                                native_blake_prefix_compressions=native["blake_prefix_compressions"]),
                  derived=dict(recursion_ns_per_padded_cell=ns_per_cell))
    for variant in (a.baseline_variant, a.variant):
        r = rates(kernel, variant)
        wide, narrow = r["479x2^20"], r["128x2^20"]
        native_p2 = [native["p2_prefix_permutations"] / x["p2_perm_per_s"] for x in (wide, narrow)]
        native_blake = native["blake_prefix_compressions"] / wide["blake_compress_per_s"]
        native_delta = [x - native_blake for x in native_p2]

        pure = LEAF_PURE_P2_CELLS / LEAF_BLAKE_CELLS
        mixed = LEAF_MIXED_CELLS / LEAF_BLAKE_CELLS
        # (a) all-Poseidon: leaves at the pure ratio [D on the census leaf, E on
        # production leaves]; folds verify P2 recursive proofs, ratio unmeasured,
        # banded between the pure and mixed leaf ratios [E]. Recursion proofs then
        # commit with P2: LDE cells x (P2 - Blake) per-cell hashing cost [E].
        a_leaf = cells["leaf_cells"] * pure
        a_fold = [cells["fold_cells"] * f for f in (pure, mixed)]
        a_cells = [a_leaf + f for f in a_fold]
        a_commit = [c * (1 << RECURSION_LOG_BLOWUP) * (narrow["p2_cell_ns"] - narrow["blake_cell_ns"]) / 1e9
                    for c in a_cells]
        a_rec = [c * ns_per_cell / 1e9 + k for c, k in zip(a_cells, a_commit)]
        # (b) mixed: native PCS in P2, residual Blake GKR/frame; recursion proofs and
        # folds unchanged (they still verify Blake recursive proofs) [D].
        b_cells = cells["leaf_cells"] * mixed + cells["fold_cells"]
        b_rec = b_cells * ns_per_cell / 1e9
        result[variant] = dict(
            rates_M=r,
            native_p2_hash_gpu_s_D=native_p2, native_blake_hash_gpu_s_D=native_blake,
            native_hash_delta_gpu_s_D=native_delta,
            all_poseidon=dict(recursion_cells_E=a_cells, recursion_p2_commit_overhead_gpu_s_E=a_commit,
                              recursion_gpu_s_E=a_rec,
                              net_delta_gpu_s_E=[min(native_delta) + min(a_rec) - rec_gpu_s,
                                                 max(native_delta) + max(a_rec) - rec_gpu_s],
                              request_kernel_gpu_s_E=[REQUEST_KERNEL_GPU_S + min(native_delta) + min(a_rec) - rec_gpu_s,
                                                      REQUEST_KERNEL_GPU_S + max(native_delta) + max(a_rec) - rec_gpu_s]),
            mixed=dict(recursion_cells_E=b_cells, recursion_gpu_s_E=b_rec,
                       net_delta_gpu_s_E=[min(native_delta) + b_rec - rec_gpu_s,
                                          max(native_delta) + b_rec - rec_gpu_s],
                       request_kernel_gpu_s_E=[REQUEST_KERNEL_GPU_S + min(native_delta) + b_rec - rec_gpu_s,
                                               REQUEST_KERNEL_GPU_S + max(native_delta) + b_rec - rec_gpu_s]))
    result["caveats"] = [
        "Recursion GPU-s is modelled linear in padded cells at the measured D2 after-native ns/cell; "
        "per-node fixed costs (launches, syncs, graph instantiation) do not shrink with cells.",
        "Leaf ratios come from one five-step CPU0 census leaf; production leaves verify deeper trees.",
        "Fold ratio under all-Poseidon is unmeasured and banded between the pure and mixed leaf ratios.",
        "Native P2 hashing uses the exact M7 prefix-permutation census at retained-tree kernel rates; "
        "no prefix-bank runtime, FS, PoW or opening cost is included.",
        "No proof, receiver, tamper corpus or end-to-end timing is implied."]
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: result[k] for k in (a.baseline_variant, a.variant)}, indent=1)[:3000])


if __name__ == "__main__":
    main()
