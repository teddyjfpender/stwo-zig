"""Calibrated whole-assignment residual of the rowpar witness on production
nodes (adversarial review of the README's [E] row).

The original [E] row used residual = 0.69 x 0.21 + 0.31 x 1.0 (Blake levels
x0.21, non-Blake levels unchanged). That formula, applied to the recorded
mini leaf itself (85% Blake levels), predicts x0.33 against the measured
x0.513, because the non-Blake tail gets MORE expensive under rowpar:
  * its exposed depth is 7,398 levels vs 6,050 census non-Blake levels
    (x1.22: the census classes a mixed level as Blake, hiding arithmetic depth);
  * a rowpar tail level costs ~1.55 us vs ~0.93 us per DAG narrow level.
This model calibrates three factors on the mini leaf [M, steps-leaf-blake.tsv,
gpu-leaf-d2.jsonl, level-census.jsonl] and applies them to the production
M6 level census (one row per plan) [M].

  python3 -I residual_model.py <rv64-m6 level-census.json>
"""
import json, sys

# Mini leaf calibration [M]
DAG_MS = 41.13            # chain_run + wide_level, 41,664 levels, 284 wide
WIDE_MS = 2.773           # rowpar wide steps (taken as the DAG wide cost too)
WIDE_TASKS = 2974162
MINI = dict(blake=35330, tail=3459 + 2495 + 95, wide=284)
BLAKE_ROWPAR_MS = 18.668 - 11.463   # narrow steps holding compressions
TAIL_ROWPAR_MS = 11.463             # one step, 7,398 levels, 66 compressions
TAIL_LEVELS = 7398
FILL_MS = 0.0696

narrow_us = (DAG_MS - WIDE_MS) * 1e3 / (MINI["blake"] + MINI["tail"])
f_blake = BLAKE_ROWPAR_MS * 1e3 / (MINI["blake"] * narrow_us)
f_tail = TAIL_ROWPAR_MS * 1e3 / (MINI["tail"] * narrow_us)
depth = TAIL_LEVELS / MINI["tail"]
tail_us = TAIL_ROWPAR_MS * 1e3 / TAIL_LEVELS


def node(p, tail_mode):
    blake = p["blake_g_levels"]
    tail = p["mul_levels"] + p["other_levels"] + p["inverse_levels"] + p["permutation_levels"]
    wide = WIDE_MS * p["wide_tasks"] / WIDE_TASKS
    dag = (blake + tail) * narrow_us / 1e3 + wide
    if tail_mode == "calibrated":     # mini-leaf tail factor (depth x per-level)
        t = tail * narrow_us * f_tail / 1e3
    elif tail_mode == "lower":        # no hidden depth, rowpar per-level cost
        t = tail * tail_us / 1e3
    else:                             # hybrid: tail on chain_run per-level cost
        t = tail * narrow_us * depth / 1e3
    rp = blake * narrow_us * f_blake / 1e3 + t + wide + FILL_MS
    return dag, rp


def main():
    census = json.load(open(sys.argv[1]))["plans"]
    out = {"label": "D/E", "narrow_us_per_dag_level": round(narrow_us, 3), "f_blake": round(f_blake, 3),
           "f_tail": round(f_tail, 3), "tail_depth_factor": round(depth, 3), "tail_us_per_rowpar_level": round(tail_us, 3),
           "mini_check_original_formula": round((MINI["blake"] * 0.21 + MINI["tail"]) / (MINI["blake"] + MINI["tail"]), 3),
           "mini_measured": 0.513}
    for mode in ("calibrated", "lower", "hybrid"):
        leaves = [p for p in census if p["blake_g_levels"] + p["mul_levels"] > 20000]
        folds = [p for p in census if p not in leaves]
        for name, rows in (("leaf", leaves), ("fold", folds)):
            d = r = 0.0
            rs = []
            for p in rows:
                a, b = node(p, mode)
                d += a; r += b; rs.append(b / a)
            out[f"{mode}_{name}_residual_weighted"] = round(r / d, 3)
            out[f"{mode}_{name}_residual_min_max"] = [round(min(rs), 3), round(max(rs), 3)]
            out[f"{mode}_{name}_dag_ms_sum"] = round(d, 1)
        d = r = 0.0
        for p in census:
            a, b = node(p, mode); d += a; r += b
        out[f"{mode}_all_residual_weighted"] = round(r / d, 3)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
