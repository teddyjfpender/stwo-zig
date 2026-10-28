#!/usr/bin/env python3
"""Validate paired complete-bundle mode0/mode1 measurements, without timing extrapolation."""
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
    if (not re.search(r"All \d+ tests passed\.", text) or "FAIL (" in text or
            "errors were logged" in text or "tests leaked memory" in text or
            "test command failed" in text):
        raise ValueError("Incomplete or failed comparison")
    begin, end, matched = {}, {}, []
    negatives = []
    for line in text.splitlines():
        for marker, target in (("BLOCK_V6_REGISTER_BEGIN", begin), ("BLOCK_V6_REGISTER_COMPLETE", end)):
            if marker + " " in line:
                row = fields(line, marker)
                if row["mode"] in target:
                    raise ValueError("Repeated mode; use a separate log for each pair")
                target[row["mode"]] = row
        if "BLOCK_V6_REGISTER_MATCHED " in line:
            matched.append(fields(line, "BLOCK_V6_REGISTER_MATCHED"))
        if "BLOCK_V6_REGISTER_NEGATIVE " in line:
            negatives.append(fields(line, "BLOCK_V6_REGISTER_NEGATIVE"))
    if set(begin) != {0, 1} or set(end) != {0, 1} or len(matched) != 1:
        raise ValueError("Missing complete matched pair")
    if negatives != [{"cancelling_claims": "rejected", "error": "OodsNotMatching"}]:
        raise ValueError("Missing hostile physical-claim rejection")
    for mode in (0, 1):
        a, b = begin[mode], end[mode]
        for key in ("mode", "profile", "iterations", "cycles", "segments"):
            if a[key] != b[key]:
                raise ValueError("Input/output mismatch")
        if b["verified"] != "true" or b["complete_bundle"] != "true" or b["standalone_root"] != "false":
            raise ValueError("Wrong verification scope")
        if b["segments"] != 2 or b["cycles"] != 5 * b["iterations"] + 14:
            raise ValueError("Unexpected guest geometry")
        for key in ("memory_cells", "events", "base_files", "charged_peak_bytes", "wall_ns", "memory_range_ns"):
            if not isinstance(b[key], int) or b[key] <= 0:
                raise ValueError("Invalid measured value")
        partition = sum(b[k] for k in ("collection_ns", "proving_ns", "forest_ns", "verification_ns"))
        if partition > b["wall_ns"]:
            raise ValueError("Driver phases exceed enclosing wall time")
        b["driver_unpartitioned_ns"] = b["wall_ns"] - partition
    left, right = end[0], end[1]
    for key in ("profile", "iterations", "cycles", "segments", "initial_rw", "final_rw"):
        if left[key] != right[key]:
            raise ValueError("Mismatched public workload")
    pair = matched[0]
    if (pair["profile"] != left["profile"] or pair["cycles"] != left["cycles"] or
            pair["mode0_events"] != left["events"] or pair["mode1_events"] != right["events"] or
            pair["same_elf_input_endpoints"] != "true" or pair["complete_bundles"] != "true" or
            left["events"] <= right["events"] or right["events"] < 2 * right["iterations"]):
        raise ValueError("Invalid matched census")
    batches = [fields(line, "BLOCK_V6_COMPLETE_BATCH") for line in text.splitlines()
               if "BLOCK_V6_COMPLETE_BATCH " in line]
    controls = [fields(line, "BLOCK_V6_COMPLETE_BATCH_NEGATIVE") for line in text.splitlines()
                if "BLOCK_V6_COMPLETE_BATCH_NEGATIVE " in line]
    direct = [fields(line, "BLOCK_V6_DIRECT_NATIVE") for line in text.splitlines()
              if "BLOCK_V6_DIRECT_NATIVE " in line]
    if len(batches) > 1 or bool(batches) != bool(controls):
        raise ValueError("Incomplete direct-batch follow-up")
    if batches:
        batch = batches[0]
        if (batch["verified"] != "true" or batch["standalone_root"] != "false" or
                batch["replacement_driver"] != "false" or batch["profile"] != right["profile"] or
                batch["segments"] != right["segments"] or len(controls) != 1 or
                controls[0] != {"tampered_proof": "rejected", "error": "OodsNotMatching"}):
            raise ValueError("Invalid direct-batch verification scope")
        for key in ("capture_ns", "batch_wall_ns", "recursive_phase_ns", "complete_receive_ns", "recursive_cells", "charged_peak_bytes", "batch_bytes"):
            if not isinstance(batch[key], int) or batch[key] <= 0:
                raise ValueError("Invalid direct-batch measurement")
        if batch["recursive_phase_ns"] > batch["batch_wall_ns"]:
            raise ValueError("Batch phases exceed enclosing timer")
        if len(direct) != 1:
            raise ValueError("Missing direct-native phase partition")
        proof = direct[0]
        if (proof["verified"] != "true" or proof["globals_open"] != "true" or
                proof["profile"] != batch["profile"] or proof["children"] != batch["segments"] or
                proof["recursive_ns"] != batch["recursive_phase_ns"] or
                sum(proof[k] for k in ("prepare_ns", "setup_ns", "prove_ns", "encode_verify_ns")) != proof["recursive_ns"] or
                proof["air_cells"] != batch["recursive_cells"] or proof["proof_bytes"] != batch["batch_bytes"]):
            raise ValueError("Direct-native proof/fresh receiver mismatch")
    elif direct:
        raise ValueError("Direct proof lacks complete receiver result")
    return {"log": path.name, "sha256": hashlib.sha256(raw).hexdigest(),
            "begin": [begin[0], begin[1]], "measurements": [left, right],
            "negative_controls": negatives,
            "complete_native_batch_followup": batches,
            "complete_native_batch_negative_controls": controls,
            "direct_native_proof": direct,
            "mode0_over_mode1": {k: left[k] / right[k] for k in
                ("wall_ns", "memory_range_ns", "events", "byte_requests", "memory_cells", "charged_peak_bytes")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()
    print(json.dumps({"schema": "stwo-zig/register-custody-comparison/v1",
        "scope": "Same real ELF with register/RAM loop, SHA and Keccak; complete detached bundles, not standalone recursive block roots",
        "timing": "Driver wall excludes shared preflight and source initialization; family counters overlap other work and are not additive wall phases",
        "memory": "Aggregate driver allocator accounting, not process RSS",
        "samples": [parse(path) for path in args.logs]}, indent=2))


if __name__ == "__main__":
    main()
