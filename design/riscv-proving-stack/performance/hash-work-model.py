#!/usr/bin/env python3
"""Read actual G-row census; model alternative PCS work, never elapsed time.

Input must be a sequential STWO_RISCV_HASH_WORK_CENSUS log. A capture ends at
its TOTAL line. The current schedule must reproduce exactly before alternatives
are reported. Wider folding, domain keys and vertical batching are NOT qualified
protocols by this model. Lookup, routing, arithmetic and transcript growth are
outside the counterfactual PCS comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path


def compression_g(nbytes):
    return 56 * (max(1, (nbytes + 63) // 64) + max(1, (nbytes + 1023) // 1024) - 1)


def upper_nodes(depth, queries, frontier):
    if not queries:
        return 0
    if frontier == "current":
        removed = 2 * queries - 3 if depth >= 2 and queries > 1 else queries - 1 if depth == 1 else 0
        return queries * depth - removed
    # Complete fixed frontier: every query proves its route into the cap.
    # Count only hashes here, not selection/routing constraints or witnesses.
    return min(queries * (depth - k) + (1 << k) - 1 for k in range(depth + 1))


def tree_work(words, leaves, depth, queries, node_g=112, frontier="current"):
    return (queries * leaves * compression_g(28 + 4 * words)
            + queries * (leaves - 1) * node_g
            + upper_nodes(depth, queries, frontier) * node_g)


def pcs_work(trees, fold=1, batch_log=0, node_g=112, frontier="current"):
    trace = [t for t in trees if t["kind"] == "trace"]
    fri = [t for t in trees if t["kind"] == "fri"]
    if not fri or any(t["words"] != 4 or t["leaves"] != 2 for t in fri):
        raise ValueError("model requires an observed fold-one schedule")
    start = fri[0]["depth"] + 1
    final = fri[-1]["depth"]
    if [t["depth"] for t in fri] != list(range(start - 1, final - 1, -1)):
        raise ValueError("non-contiguous FRI census")
    queries = fri[0]["queries"]
    if any(t["queries"] != queries for t in trees):
        raise ValueError("mixed query counts")
    result = sum(tree_work(t["words"], t["leaves"], t["depth"] + batch_log,
                           queries, node_g, frontier) for t in trace)
    remaining = start + batch_log
    layers = 0
    while remaining > final:
        step = min(fold, remaining - final)
        remaining -= step
        width = 4 if step > 1 else 1
        result += tree_work(width * 4, (1 << step) // width, remaining,
                            queries, node_g, frontier)
        layers += 1
    return result, layers


def analyze(trees, actual):
    for key in ("leaf_g", "subtree_g", "upper_g", "unique_leaf_g", "unique_subtree_g", "unique_upper_g"):
        if sum(t[key] for t in trees) != actual[key]:
            raise ValueError(f"non-conserving {key}")
    baseline, _ = pcs_work(trees)
    if baseline != actual["paths_g"] or baseline + actual["transcript_g"] != actual["total_g"]:
        raise ValueError("baseline model does not reproduce capture")
    optimistic = sum(actual[k] for k in ("unique_leaf_g", "unique_subtree_g", "unique_upper_g"))
    variants = []
    for fold, frontier, node in ((2, "current", 112), (4, "current", 112),
                                 (4, "optimal", 112), (4, "optimal", 56)):
        work, layers = pcs_work(trees, fold, node_g=node, frontier=frontier)
        variants.append(dict(fold_step=fold, frontier=frontier, node_g=node,
                             pcs_g=work, fri_layers=layers, pcs_work_ratio=baseline / work))
    # Vertical batching requires compatible AIRs and proved segment boundaries.
    # Here the leaf width is fixed and every domain grows by log2(batch).
    # This is not a model of horizontally concatenated component proofs.
    batches = []
    for batch_log in (1, 2, 3, 4):
        work, layers = pcs_work(trees, fold=4, batch_log=batch_log, frontier="optimal")
        batches.append(dict(batch_size=1 << batch_log, pcs_g=work, fri_layers=layers,
                            pcs_work_ratio=(1 << batch_log) * baseline / work,
                            largest_merkle_log=max(t["depth"] for t in trees) + batch_log))
    return dict(actual=actual, trees=trees,
                ideal_topology_pcs_g=optimistic,
                ideal_topology_pcs_ratio=baseline / optimistic,
                ideal_topology_total_g_ratio=actual["total_g"] / (optimistic + actual["transcript_g"]),
                counterfactuals=variants, vertical_batch_counterfactuals=batches)


def parse(text):
    trees, captures = [], []
    for line in text.splitlines():
        marker = "BLAKE3_HASH_WORK"
        start = line.find(marker)
        if start < 0:
            continue
        kind, *fields = line[start:].split()
        record = {}
        for field in fields:
            name, value = field.split("=", 1)
            record[name] = value if name == "kind" else int(value)
        if kind == marker:
            trees.append(record)
        elif kind == marker + "_TOTAL":
            captures.append(analyze(trees, record))
            trees = []
    if trees or not captures:
        raise ValueError("missing or truncated capture census")
    return captures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--native-prefix", type=int, default=0,
                        help="Known fixture: first N captures are native children; all later captures verify wrappers. Models omitted wrapper G work, excluding the new batch bus.")
    args = parser.parse_args()
    data = args.log.read_bytes()
    captures = parse(data.decode())
    output = dict(scope="Measured planned G rows; counterfactual PCS hash work only, not proofs, security certification, memory peaks or runtime. Transcript growth, arithmetic, routing, lookup providers and capacity feasibility excluded from counterfactuals.",
                  source_log_sha256=hashlib.sha256(data).hexdigest(), captures=captures)
    output["completion_evidence"] = [line for line in data.decode().splitlines()
                                     if "BLOCK_V5_CPU_COMPLETE" in line or line.startswith("All ")]
    if args.native_prefix:
        if not 0 < args.native_prefix < len(captures):
            raise ValueError("invalid native capture prefix")
        old = sum(c["actual"]["total_g"] for c in captures)
        native = sum(c["actual"]["total_g"] for c in captures[:args.native_prefix])
        output["direct_native_batch_counterfactual"] = dict(
            native_children=args.native_prefix, current_recursive_g=old,
            native_verifier_g=native, omitted_wrapper_verifier_g=old-native,
            g_work_ratio_before_new_batch_binding=old/native,
            scope="Requires replacing wrapper-only admissions with direct native admission, complete public-supply and segment-boundary constraints. Does not close global obligations or predict proof time.")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
