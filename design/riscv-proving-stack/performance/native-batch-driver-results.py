#!/usr/bin/env python3
"""Parse matched original/replacement driver runs, preserving timing scope."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def fields(line, marker):
    values = dict(re.findall(r"(\w+)=([^\s]+)", line.split(marker + " ", 1)[1]))
    return {k: int(v) if v.isdecimal() else v for k, v in values.items()}


def parse(path):
    raw = path.read_bytes()
    text = raw.decode()
    if (not re.search(r"All \d+ tests passed\.", text) or any(s in text for s in
            ("FAIL (", "errors were logged", "tests leaked memory", "test command failed"))):
        raise ValueError("Run did not complete cleanly")
    samples = {}
    active = None
    for line in text.splitlines():
        for marker in ("BLOCK_V6_REGISTER_BEGIN", "BLOCK_V6_REGISTER_COMPLETE", "BLOCK_V6_REGISTER_MATCHED", "BLOCK_V6_DRIVER_NEGATIVE", "BLOCK_V6_DRIVER"):
            if marker + " " not in line:
                continue
            row = fields(line, marker)
            if marker == "BLOCK_V6_REGISTER_BEGIN":
                active = row["profile"]
                sample = samples.setdefault(active, {"begin": {}, "baseline": {}, "driver": [], "controls": [], "matched": []})
                if row["mode"] in sample["begin"]:
                    raise ValueError("Repeated profile/mode")
                sample["begin"][row["mode"]] = row
            else:
                if active is None:
                    raise ValueError("Result precedes workload")
                sample = samples[active]
                if "profile" in row and row["profile"] != active:
                    raise ValueError("Wrong profile")
                if marker == "BLOCK_V6_REGISTER_COMPLETE":
                    if row["mode"] in sample["baseline"]:
                        raise ValueError("Repeated baseline")
                    sample["baseline"][row["mode"]] = row
                else:
                    sample[{"BLOCK_V6_DRIVER": "driver", "BLOCK_V6_DRIVER_NEGATIVE": "controls", "BLOCK_V6_REGISTER_MATCHED": "matched"}[marker]].append(row)
    if not samples:
        raise ValueError("No completed comparisons")
    for profile, sample in samples.items():
        if (set(sample["begin"]) != {0, 1} or set(sample["baseline"]) != {0, 1} or
                len(sample["driver"]) != 1 or len(sample["matched"]) != 1 or
                sample["controls"] != [{"changed_identity": "rejected", "cancelling_claims": "OodsNotMatching", "cold_after_owner_destruction": "true"}]):
            raise ValueError("Incomplete matched comparison or hostile controls")
        old = sample["baseline"][1]
        new = sample["driver"][0]
        matched = sample["matched"][0]
        left = sample["baseline"][0]
        for key in ("iterations", "cycles", "segments", "initial_rw", "final_rw"):
            if left[key] != old[key]:
                raise ValueError("Baseline arms prove different workloads")
        if (matched["profile"] != profile or matched["cycles"] != old["cycles"] or
                matched["same_elf_input_endpoints"] != "true" or matched["complete_bundles"] != "true" or
                matched["mode0_events"] != left["events"] or matched["mode1_events"] != old["events"]):
            raise ValueError("Invalid matched census")
        for mode in (0, 1):
            baseline = sample["baseline"][mode]
            for key in ("profile", "iterations", "cycles", "segments"):
                if baseline[key] != sample["begin"][mode][key]:
                    raise ValueError("Workload mismatch")
            if baseline["verified"] != "true" or baseline["complete_bundle"] != "true" or baseline["standalone_root"] != "false":
                raise ValueError("Baseline scope mismatch")
        if (new["verified"] != "true" or new["replacement_driver"] != "true" or new["standalone_root"] != "false" or
                new["baseline_wall_ns"] != old["wall_ns"] or new["segments"] != old["segments"] or new["base_files"] != old["base_files"]):
            raise ValueError("Replacement scope mismatch")
        if any(not isinstance(new[k], int) or new[k] <= 0 for k in ("wall_ns", "collection_ns", "base_ns", "recursive_ns", "verification_ns", "prepare_ns", "setup_ns", "prove_ns", "encode_ns", "detached_ns", "charged_peak_bytes", "batch_bytes")):
            raise ValueError("Invalid measurement")
        partition = sum(new[k] for k in ("collection_ns", "base_ns", "recursive_ns", "verification_ns"))
        if partition > new["wall_ns"] or sum(new[k] for k in ("prepare_ns", "setup_ns", "prove_ns", "encode_ns")) > new["recursive_ns"]:
            raise ValueError("Phase partition exceeds wall timer")
        new["unpartitioned_ns"] = new["wall_ns"] - partition
        sample["speedup"] = old["wall_ns"] / new["wall_ns"]
        sample["peak_ratio_old_over_new"] = old["charged_peak_bytes"] / new["charged_peak_bytes"]
    return {"log": path.name, "log_sha256": hashlib.sha256(raw).hexdigest(), "samples": samples}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(json.dumps({"schema": "stwo-zig/native-batch-driver/v1",
        "scope": "Complete bundles including original global base proofs; single native batch, not standalone block root",
        "timing": "Actual driver invocation including publication and fresh complete verification; shared preflight/source initialization excluded; extra detached and hostile probes excluded",
        "memory": "Whole driver shared allocator peak, not RSS; family times overlap and are not additive",
        **parse(args.log)}, indent=2))
