#!/usr/bin/env python3
"""Diagnostic CPU cost model; never a full-block proof or qualified ETA."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[3]
CAMPAIGN = ROOT / "vectors/reports/riscv-cpu-architecture-20261029"
CENSUS = ROOT / "vectors/reports/v7-runpod-gpu-20261029/full-execution-census"
LEDGER = ROOT / "vectors/reports/riscv-frontend-work-ledger-20261029"
OUT = CAMPAIGN / "full-block-cost-model-v1"


def load(path: Path):
    return json.loads(path.read_text())


def digest(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def case(cycles: int):
    suffix = "single" if cycles <= 1 << 23 else "2x8388608"
    folder = CAMPAIGN / f"native-{cycles}-direct-clock-v3-wide-{suffix}-sparse-compact-profile4"
    source_path, root_path = folder / "report.json", Path(str(folder) + "-single-dag-root") / "report.json"
    source, recursive = load(source_path), load(root_path)
    assert recursive["fresh_verified"] and recursive["source_execution_count"] == recursive["source_reproof_count"] == 0
    assert recursive["source_captures"] == source["stats"]["cohorts"] + 2 and recursive["snapshot_delta_public_ports"] == 0
    assert recursive["queries"] == 70 and recursive["pow_bits"] == 26
    assert source["window"] == recursive["window"] == {"skip_cycles": 1, "cycles": cycles}
    # Prefix geometry only, NOT an artifact decoder or verifier. This geometry
    # was independently admitted by the saved original/root verification runs.
    cells = 0
    for i in range(source["stats"]["cohorts"]):
        encoded = bytes.fromhex(load(folder / f"artifacts/local-{i}.json")["shape"])
        count = struct.unpack_from("<I", encoded)[0]
        assert 0 < count <= 256
        descriptors = [struct.unpack_from("<BIII", encoded, 4 + 13 * j) for j in range(count)]
        cells += sum((1 << log) * (width + (5 if family == 12 else 0)) for family, log, _, width in descriptors)
    return dict(cycles=cycles,
                originals_s=source["whole_including_loading_and_publication_ns"] / 1e9,
                recursion_s=recursive["whole_ns"] / 1e9,
                root_core_s=recursive["parent"]["proof_ns"] / 1e9,
                root_receiver_s=recursive["fresh_receiver_ns"] / 1e9,
                root_peak_bytes=recursive["charged_peak_bytes"],
                root_bytes=recursive["root_bytes"], root_sha256=recursive["root_sha256"],
                native_main_cell_proxy=cells,
                source_report_sha256=digest(source_path), root_report_sha256=digest(root_path))


def interpolate(left, right, cycles, field):
    fraction = (cycles - left["cycles"]) / (right["cycles"] - left["cycles"])
    assert 0 <= fraction <= 1, "Do not extrapolate per-window sizes beyond measured range"
    return left[field] + fraction * (right[field] - left[field])


def main():
    ledger, metadata, census = load(LEDGER / "ledger.json"), load(LEDGER / "encoding-metadata.json"), load(CENSUS / "summary.json")
    for name in ("summary.json", "segments.jsonl"):
        assert digest(CENSUS / name) == ledger["inputs"][name]
    assert digest(LEDGER / "encoding-metadata.json") == ledger["inputs"]["encoding-metadata.json"]
    segments = [json.loads(line) for line in (CENSUS / "segments.jsonl").read_text().splitlines() if line]
    families = metadata["families"]
    assert len(families) == 17 and families[12]["name"] == "load_store"
    small, large = case(1 << 22), case(1 << 23)
    assert sum(s["counts"]["cycles"] for s in segments) == census["expected_cycles"] == 139214856
    windows = []
    for start in range(0, len(segments), 16):
        chunk = segments[start:start + 16]
        counts = [sum(s["counts"]["families"][i] for s in chunk) for i in range(17)]
        cycles = sum(s["counts"]["cycles"] for s in chunk)
        cells = sum((1 << max(1, (rows - 1).bit_length())) * (f["main_columns"] + (5 if i == 12 else 0))
                    for i, (rows, f) in enumerate(zip(counts, families)) if rows)
        source_s = interpolate(small, large, cycles, "originals_s")
        root_s = interpolate(small, large, cycles, "recursion_s")
        reference_cells = interpolate(small, large, cycles, "native_main_cell_proxy")
        windows.append(dict(window=len(windows), first_cycle=chunk[0]["first_cycle"], cycles=cycles,
                            native_rows=sum(counts), active_native_families=sum(bool(c) for c in counts),
                            keccak_calls=sum(s["counts"]["keccak_calls"] for s in chunk),
                            recovery_calls=sum(s["counts"]["recovery_calls"] for s in chunk),
                            sha_calls=sum(s["counts"]["sha_calls"] for s in chunk),
                            wide_native_main_cell_proxy=cells,
                            native_only_originals_s=source_s, native_only_recursion_s=root_s,
                            source_area_sensitivity_s=source_s * cells / reference_cells))
    source_s = sum(w["native_only_originals_s"] for w in windows)
    recursion_s = sum(w["native_only_recursion_s"] for w in windows)
    adjusted_source_s = sum(w["source_area_sensitivity_s"] for w in windows)
    subtotal = source_s + recursion_s
    result = dict(schema="stwo-native-cpu-full-block-cost-sensitivity-v1", proof_verified=False,
                  qualified_full_block_eta=False, cpu_only=True, queries=70, pow_bits=26,
                  original_workers=8, recursive_core_workers=8, recursive_source_jobs=2,
                  measured_cases=[small, large], full_execution_cycles=census["expected_cycles"],
                  modeled_windows=len(windows), upper_binary_nodes=len(windows)-1,
                  windows_with_unqualified_caller_route=sum(bool(w["keccak_calls"] or w["recovery_calls"] or w["sha_calls"]) for w in windows),
                  actual_keccak_calls=sum(w["keccak_calls"] for w in windows),
                  actual_recovery_calls=sum(w["recovery_calls"] for w in windows),
                  native_only_originals_s=source_s, native_only_window_recursion_s=recursion_s,
                  native_only_serial_subtotal_s=subtotal,
                  native_main_area_sensitivity_originals_s=adjusted_source_s,
                  native_main_area_sensitivity_subtotal_s=adjusted_source_s + recursion_s,
                  upper_fold_sensitivity=[dict(ASSUMED_seconds_per_node=fold,
                                               native_only_serial_minutes=(subtotal + (len(windows)-1)*fold)/60)
                                          for fold in (0, 10, 30, 60, 120)],
                  unknown_terms=["mixed-caller source/profile integration and recursive cost",
                                 "qualified upper-root verifier with public-supply closure and adjacent snapshot/CPU binding",
                                 "skipped prefix and actual terminal/output binding",
                                 "whole-block peak memory and complete final-root verification"],
                  boundaries=["Measured originals and recursion are SEPARATE cold runs; their sum is not an end-to-end observation.",
                              "Serial model uses current detached-file workflow, including its recorded fresh verification stages.",
                              "Native-equivalent only: profile4 currently rejects caller-containing sources.",
                              "8M plan sizes interpolate between measured 4M/8M; 16M plan uses the actual 2-cohort16M case plus an interpolated 5M tail. Workload composition is extrapolated.",
                              "Area sensitivity is an UNVALIDATED work proxy, not a regression or confidence interval.",
                              "Closed-window root costs already include bridge/global RAM: do not add another full-block global proof.",
                              "Upper-fold table is sensitivity to ASSUMED costs; no upper-fold timing was measured.",
                              "No complete Ethereum block or adjacent window-root hierarchy has been proved by this model."],
                  inputs={"execution_summary_sha256":digest(CENSUS/"summary.json"),
                          "execution_segments_sha256":digest(CENSUS/"segments.jsonl"),
                          "encoding_metadata_sha256":digest(LEDGER/"encoding-metadata.json"),
                          "script_sha256":digest(Path(__file__))})
    final = case(1 << 24)
    windows16 = []
    for start in range(0, len(segments), 32):
        chunk = segments[start:start + 32]
        cycles = sum(s["counts"]["cycles"] for s in chunk)
        cells = 0
        for child_start in range(0, len(chunk), 16):
            child = chunk[child_start:child_start + 16]
            for i, family in enumerate(families):
                rows = sum(s["counts"]["families"][i] for s in child)
                if rows:
                    cells += (1 << max(1, (rows - 1).bit_length())) * (family["main_columns"] + (5 if i == 12 else 0))
        exact = cycles == final["cycles"]
        source_s16 = final["originals_s"] if exact else interpolate(small, large, cycles, "originals_s")
        root_s16 = final["recursion_s"] if exact else interpolate(small, large, cycles, "recursion_s")
        ref_cells = final["native_main_cell_proxy"] if exact else interpolate(small, large, cycles, "native_main_cell_proxy")
        windows16.append(dict(window=len(windows16), first_cycle=chunk[0]["first_cycle"], cycles=cycles,
                              execution_cohorts=(len(chunk)+15)//16,
                              keccak_calls=sum(s["counts"]["keccak_calls"] for s in chunk),
                              recovery_calls=sum(s["counts"]["recovery_calls"] for s in chunk),
                              native_main_cell_proxy=cells,
                              native_only_originals_s=source_s16, native_only_recursion_s=root_s16,
                              source_area_sensitivity_s=source_s16*cells/ref_cells))
    source16 = sum(w["native_only_originals_s"] for w in windows16)
    root16 = sum(w["native_only_recursion_s"] for w in windows16)
    subtotal16 = source16 + root16
    result["measured_cases"].append(final)
    result["native_16m_window_plan"] = dict(modeled_windows=len(windows16), upper_binary_nodes=len(windows16)-1,
        windows_with_unqualified_caller_route=sum(bool(w["keccak_calls"] or w["recovery_calls"]) for w in windows16),
        native_only_originals_s=source16, native_only_recursion_s=root16,
        native_only_serial_subtotal_s=subtotal16,
        native_main_area_sensitivity_subtotal_s=sum(w["source_area_sensitivity_s"] for w in windows16)+root16,
        reduction_vs_8m_native_serial_fraction=1-subtotal16/subtotal,
        upper_fold_sensitivity=[dict(ASSUMED_seconds_per_node=fold,
                                    native_only_serial_minutes=(subtotal16+(len(windows16)-1)*fold)/60)
                                for fold in (0,10,30,60,120)])
    OUT.mkdir(exist_ok=True)
    (OUT / "model.json").write_text(json.dumps(result, indent=2) + "\n")
    with (OUT / "windows.csv").open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(windows[0]))
        writer.writeheader()
        writer.writerows(windows)
    with (OUT / "windows-16m.csv").open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(windows16[0]))
        writer.writeheader()
        writer.writerows(windows16)
    print(json.dumps(result["native_16m_window_plan"]))
    print(json.dumps({k: result[k] for k in ("modeled_windows", "windows_with_unqualified_caller_route", "native_only_originals_s", "native_only_window_recursion_s", "native_only_serial_subtotal_s", "native_main_area_sensitivity_subtotal_s")}))


if __name__ == "__main__":
    main()
