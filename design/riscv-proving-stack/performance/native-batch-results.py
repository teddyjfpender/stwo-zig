#!/usr/bin/env python3
"""Summarize completed, matched direct-native/wrapper proof experiments.

Pass full logs, not grepped timing lines: failed/incomplete runs are rejected.
All results describe an open-global two-native fixture, not an Ethereum block.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics

PROFILE = "csp_q70_pow26"


def record(line, marker):
    text = line.split(marker + " ", 1)[1]
    fields = dict(re.findall(r"(\w+)=([^\s]+)", text))
    return {key: int(value) if value.isdecimal() else value for key, value in fields.items()}


def read(path):
    raw = path.read_bytes()
    text = raw.decode()
    if not re.search(r"All \d+ tests passed\.", text) or "FAIL (" in text:
        raise ValueError(f"{path.name}: incomplete or failed proof run")
    entries = {}
    workers = []
    for line in text.splitlines():
        if "BLOCK_V6_BENCH_ENV " in line:
            env = record(line, "BLOCK_V6_BENCH_ENV")
            if env["profile"] == PROFILE:
                workers.append(env["workers"])
        for name, marker in (("direct", "BLOCK_V6_DIRECT_NATIVE"), ("wrappers", "BLOCK_V6_WRAPPER_BASELINE")):
            if marker + " " not in line:
                continue
            row = record(line, marker)
            if row["profile"] != PROFILE:
                continue
            if name in entries:
                raise ValueError(f"{path.name}: duplicate {name} timing")
            if row["children"] != 2 or row["globals_open"] != "true":
                raise ValueError(f"{path.name}: unexpected statement scope")
            for key in ("native_ns", "recursive_ns", "g_rows", "air_cells", "proof_bytes"):
                if not isinstance(row.get(key), int) or row[key] <= 0:
                    raise ValueError(f"{path.name}: missing/invalid {key}")
            if name == "direct":
                parts = [row[key] for key in ("prepare_ns", "setup_ns", "prove_ns", "encode_verify_ns")]
                if row.get("verified") != "true" or sum(parts) != row["recursive_ns"]:
                    raise ValueError(f"{path.name}: direct verification/timing partition mismatch")
            row["native_plus_recursive_ns"] = row["native_ns"] + row["recursive_ns"]
            entries[name] = row
    if entries.keys() != {"direct", "wrappers"} or len(workers) != 2 or workers[0] != workers[1]:
        raise ValueError(f"{path.name}: missing matched paths/worker configuration")
    return {"log": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "workers": workers[0], **entries}


def summarize(samples):
    if len({sample["workers"] for sample in samples}) != 1:
        raise ValueError("Do not pool different worker configurations")
    for path in ("direct", "wrappers"):
        for key in ("g_rows", "air_cells", "proof_bytes"):
            if len({sample[path][key] for sample in samples}) != 1:
                raise ValueError(f"Nonidentical proof geometry/bytes across {path} samples")
    medians = {path: {key: statistics.median(sample[path][key] for sample in samples)
                      for key in ("native_ns", "recursive_ns", "native_plus_recursive_ns", "g_rows", "air_cells", "proof_bytes")}
               for path in ("direct", "wrappers")}
    ratios = {key: medians["wrappers"][key] / medians["direct"][key] for key in medians["direct"]}
    # An intentionally optimistic scaling counterfactual: every future native
    # verifier has this fixture's cost and upper-parent geometry never grows.
    # This prevents a two-leaf speedup being advertised as a whole-tree ratio.
    native_g = medians["direct"]["g_rows"] / 2
    parent_g = medians["wrappers"]["g_rows"] - 2 * native_g
    tree_model = []
    for count in (67, 512, 4096):
        old = count * native_g + (count - 1) * parent_g
        for batch in (4, 8, 16):
            batches = (count + batch - 1) // batch
            new = count * native_g + (batches - 1) * parent_g
            tree_model.append({"native_proofs": count, "batch_size": batch, "batch_proofs": batches,
                               "upper_binary_parents": batches - 1, "old_g": old, "new_g": new,
                               "work_ratio": old / new, "implemented_count_cap": batch <= 8})
    return {"medians": medians, "wrapper_over_direct_ratios": ratios,
            "tree_work_counterfactual": {"assumptions": "Uniform tiny-native cost and unchanged upper-parent cost; excludes global proofs, batch binding, padding and changed parent geometry. Not runtime or capacity qualification. Only two-child batches have proof evidence here.", "rows": tree_model}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path, nargs="+")
    args = parser.parse_args()
    samples = [read(path) for path in args.logs]
    print(json.dumps({
        "schema": "stwo-zig/direct-native-batch-comparison/v1",
        "scope": "Two real adjacent one-instruction native proofs; global providers remain open",
        "profile": PROFILE,
        "timing_scope": "Recursive preparation, key/setup, proving and encode/fresh verification; baseline excludes its deliberate invalid-edge graph probe",
        "limitations": ["Tiny fixture, not a block speedup", "No GPU measurement", "AIR cells exclude lookup providers and PCS/quotient expansion", "Final proof bytes exclude retained native and intermediate proofs", "Native-plus-recursive is a phase sum, not complete command latency", "Baseline includes small harness checks outside the excluded graph probe"],
        "samples": samples,
        **summarize(samples),
    }, indent=2))


if __name__ == "__main__":
    main()
