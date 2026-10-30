#!/usr/bin/env python3
"""Parse complete closed-bundle tiling runs; do not extrapolate block times."""
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path


def fields(text):
    pairs = [piece.split("=", 1) for piece in text.split()]
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate field")
    return result


def parse(path):
    raw = path.read_bytes()
    text = raw.decode()
    if not re.search(r"All [1-9][0-9]* tests passed\.|[1-9][0-9]* passed; [0-9]+ skipped; 0 failed\.", text) or re.search(r"\bFAIL\b|error:|memory address .* leaked", text):
        raise ValueError(f"incomplete or failed qualification: {path}")
    begin, rows, matched, checkpoint_io = {}, [], [], {}
    access_io, provider_io, ram_io = {}, {}, {}
    for line in text.splitlines():
        if "BLOCK_V6_CLOSED_TILE_BEGIN " in line:
            row = fields(line.split("BLOCK_V6_CLOSED_TILE_BEGIN ", 1)[1])
            key = int(row["segments"])
            if key in begin:
                raise ValueError("duplicate start")
            begin[key] = row
        elif "BLOCK_V6_COMMITMENT_IO " in line:
            row = fields(line.split("BLOCK_V6_COMMITMENT_IO ", 1)[1])
            if row.pop("checkpoint_dependency") != "false":
                raise ValueError("producer checkpoint used as receiver authority")
            key = int(row.pop("segments"))
            if key in checkpoint_io:
                raise ValueError("duplicate checkpoint accounting")
            checkpoint_io[key] = {key: int(value) for key, value in row.items()}
        elif "BLOCK_V6_ACCESS_IO " in line or "BLOCK_V6_PROVIDER_IO " in line or "BLOCK_V6_RAM_IO " in line:
            prefix = next(prefix for prefix in ("BLOCK_V6_ACCESS_IO ", "BLOCK_V6_PROVIDER_IO ", "BLOCK_V6_RAM_IO ") if prefix in line)
            item = fields(line.split(prefix, 1)[1])
            segment = int(item.pop("segments"))
            if prefix != "BLOCK_V6_PROVIDER_IO " and item.pop("checkpoint_dependency") != "false":
                raise ValueError("producer checkpoint used as receiver authority")
            if prefix == "BLOCK_V6_RAM_IO ":
                target, key = ram_io, segment
            else:
                retained = item.pop("retained")
                if retained not in {"true", "false"}:
                    raise ValueError("invalid retained flag")
                if prefix == "BLOCK_V6_ACCESS_IO ":
                    target, key = access_io, segment
                else:
                    target, key = provider_io, (segment, item.pop("family"))
            if key in target:
                raise ValueError("duplicate retained-provider accounting")
            target[key] = {name: int(value) for name, value in item.items()}
            if prefix != "BLOCK_V6_RAM_IO ":
                target[key]["retained"] = retained == "true"
        elif "BLOCK_V6_CLOSED_TILE_MATCHED " in line:
            matched.append(fields(line.split("BLOCK_V6_CLOSED_TILE_MATCHED ", 1)[1]))
        elif "BLOCK_V6_CLOSED_TILE verified=" in line:
            row = fields(line.split("BLOCK_V6_CLOSED_TILE ", 1)[1])
            for name, expected in (("verified", "true"), ("complete_bundle", "true"),
                                   ("standalone_root", "false"), ("negative_identity", "rejected"),
                                   ("negative_missing_proof", "rejected")):
                if row.pop(name) != expected:
                    raise ValueError(f"unqualified claim: {name}")
            row.setdefault("commitment_mode", "recomputed")
            row.setdefault("access_mode", "recomputed")
            row.setdefault("provider_mode", "recomputed")
            if row["commitment_mode"] not in {"recomputed", "retained"}:
                raise ValueError("unknown commitment mode")
            strings = {"profile", "elf_sha256", "initial_rw", "final_rw", "commitment_mode", "batch_sha256", "bundle_sha256", "access_mode", "provider_mode"}
            row = {key: value if key in strings else int(value) for key, value in row.items()}
            for key in ("elf_sha256", "initial_rw", "final_rw", *(key for key in ("batch_sha256", "bundle_sha256") if key in row)):
                if not re.fullmatch("[0-9a-f]{64}", row[key]):
                    raise ValueError("invalid source/endpoint digest")
            for key in row.keys() - strings:
                if row[key] <= 0:
                    raise ValueError(f"missing/nonpositive metric: {key}")
            phases = sum(row[name] for name in ("collection_ns", "base_ns", "recursive_ns", "verification_ns"))
            recursive = sum(row[name] for name in ("prepare_ns", "setup_ns", "prove_ns", "encode_ns"))
            if phases > row["wall_ns"] or recursive > row["recursive_ns"]:
                raise ValueError("timing partition exceeds enclosing measurement")
            row["boundary_fetches"] = row["segments"] - 1
            if row["program_fetches"] != row["cycles"] + row["boundary_fetches"]:
                raise ValueError("instruction/boundary fetch census differs")
            rows.append(row)
    if len(matched) != 1:
        raise ValueError("missing/duplicate complete comparison")
    match = matched[0]
    if match["same_elf_input_output_endpoints"] != "true" or match["fresh_global_closure"] != "true" or match["standalone_root"] != "false":
        raise ValueError("invalid equivalence scope")
    partitions = {2: {1, 4}, 3: {1, 4, 8}}.get(int(match["partitions"]))
    if partitions is None or len(rows) != len(partitions) or {r["segments"] for r in rows} != partitions or set(begin) != partitions:
        raise ValueError("missing/duplicate partition arm")
    for row in rows:
        started = begin[row["segments"]]
        for key in ("profile", "iterations", "cycles", "segments", "preflight_ns", "source_ns"):
            if str(row[key]) != started[key]:
                raise ValueError("changed workload/start record")
        if row["charged_peak_bytes"] > int(started["budget_bytes"]):
            raise ValueError("charged memory exceeds budget")
        if row["commitment_mode"] != started.get("commitment_mode", "recomputed"):
            raise ValueError("changed commitment mode")
        io = checkpoint_io.get(row["segments"])
        if row["commitment_mode"] == "retained":
            if io is None or io["reused_first_rounds"] != row["segments"]:
                raise ValueError("missing commitment reuse accounting")
            if any(value <= 0 for value in io.values()):
                raise ValueError("missing checkpoint metric")
            if io["written_bytes"] != io["checkpoint_read_bytes"] or io["column_bytes"] + io["merkle_bytes"] > io["written_bytes"]:
                raise ValueError("checkpoint byte accounting differs")
            if io["written_bytes"] > int(started["checkpoint_budget_bytes"]):
                raise ValueError("checkpoint disk budget exceeded")
            if io["write_ns"] > row["collection_ns"] or io["native_restore_ns"] > row["base_ns"]:
                raise ValueError("checkpoint time exceeds enclosing phase")
        elif io is not None:
            if any(value for key, value in io.items() if key not in {"raw_witness_read_bytes", "native_restore_ns"}):
                raise ValueError("recomputed mode claims checkpoint reuse")
            if io["raw_witness_read_bytes"] <= 0 or io["native_restore_ns"] <= 0 or io["native_restore_ns"] > row["base_ns"]:
                raise ValueError("missing recomputed load accounting")
        if io is not None:
            if set(io) != {"written_bytes", "column_bytes", "merkle_bytes", "checkpoint_read_bytes", "raw_witness_read_bytes", "write_ns", "native_restore_ns", "reused_first_rounds"}:
                raise ValueError("unknown checkpoint metrics")
            row.update({f"checkpoint_{key}": value for key, value in io.items()})
        for mode in ("access_mode", "provider_mode"):
            if row[mode] not in {"recomputed", "retained"} or row[mode] != started.get(mode, "recomputed"):
                raise ValueError("changed access/provider retention mode")
        access = access_io.get(row["segments"])
        if access is None and row["access_mode"] == "retained":
            raise ValueError("missing retained-access accounting")
        if access is not None:
            active = row["access_mode"] == "retained"
            if access["retained"] != active or any(value < 0 for value in access.values()):
                raise ValueError("invalid access accounting")
            if active:
                if access["reused_access_trees"] != row["segments"] or access["written_bytes"] <= 0 or access["written_bytes"] != access["read_bytes"]:
                    raise ValueError("incomplete access reuse")
                if access["column_bytes"] + access["merkle_bytes"] + access["raw_witness_payload_bytes"] > access["written_bytes"] or access["write_ns"] > row["collection_ns"] or access["restore_ns"] > row["base_ns"]:
                    raise ValueError("access accounting exceeds enclosing metric")
            elif any(access.values()):
                raise ValueError("recomputed access claims retention")
            row.update({f"access_{key}": value for key, value in access.items() if key != "retained"})
        for family in ("program", "lookup", "ram"):
            provider = provider_io.get((row["segments"], family))
            active = row["provider_mode"] == "retained"
            if provider is None:
                if active:
                    raise ValueError("missing retained provider")
                continue
            if provider["retained"] != active or any(value < 0 for value in provider.values()):
                raise ValueError("invalid provider accounting")
            if active:
                expected = {"program": 1, "lookup": row["lookup_groups"], "ram": row["memory_instances"] + row["range_shards"]}[family]
                if provider["reused_first_rounds"] != expected or provider["written_bytes"] <= 0 or provider["written_bytes"] != provider["read_bytes"]:
                    raise ValueError("incomplete provider reuse")
                if provider["column_bytes"] + provider["merkle_bytes"] > provider["written_bytes"] or provider["write_ns"] > row["collection_ns"] or provider["restore_ns"] > row["base_ns"]:
                    raise ValueError("provider accounting exceeds enclosing metric")
            elif any(provider.values()):
                raise ValueError("recomputed provider claims retention")
            row.update({f"{family}_{key}": value for key, value in provider.items() if key != "retained"})
        ram = ram_io.get(row["segments"])
        if ram is None and row["provider_mode"] == "retained":
            raise ValueError("missing RAM witness accounting")
        if ram is not None:
            if set(ram) != {"raw_written_bytes", "raw_read_bytes"} or ram["raw_written_bytes"] != ram["raw_read_bytes"] or any(value < 0 for value in ram.values()):
                raise ValueError("invalid RAM witness accounting")
            if row["provider_mode"] == "recomputed" and any(ram.values()):
                raise ValueError("recomputed RAM claims retention")
            row.update({f"ram_{key}": value for key, value in ram.items()})
        if row["profile"] != match["profile"] or row["cycles"] != int(match["cycles"]):
            raise ValueError("changed equivalence record")
    if set(checkpoint_io) - partitions:
        raise ValueError("unexpected checkpoint arm")
    if set(access_io) - partitions or set(ram_io) - partitions or any(segment not in partitions or family not in {"program", "lookup", "ram"} for segment, family in provider_io):
        raise ValueError("unexpected retained-provider arm")
    common = ("profile", "iterations", "cycles", "elf_sha256", "initial_rw", "final_rw", "memory_events", "byte_requests", "commitment_mode", "access_mode", "provider_mode")
    if len({tuple(row[key] for key in common) for row in rows}) != 1:
        raise ValueError("unmatched execution or global events")
    return {"log_sha256": hashlib.sha256(raw).hexdigest(), "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", type=Path, nargs="+")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("full source SHA required")
    runs = [parse(path) for path in args.logs]
    if len({run["log_sha256"] for run in runs}) != len(runs):
        parser.error("duplicate log")
    payload = {"source_commit": args.source_commit, "host": "Apple M5 Max, 64 GiB, 8 workers, ReleaseFast",
               "scope": "full driver publication and fresh global/native-batch verification; not standalone root",
               "memory_scope": "shared driver allocator peak, not process RSS",
               "family_times_overlap": True, "canonical_pow_timing_is_random": True, "runs": runs}
    args.output.with_suffix(".json").write_text(json.dumps(payload, indent=2) + "\n")
    rows = [row for run in runs for row in run["rows"]]
    with args.output.with_suffix(".csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, list(dict.fromkeys(key for row in rows for key in row)))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
