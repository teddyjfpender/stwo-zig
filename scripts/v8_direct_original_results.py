#!/usr/bin/env python3
"""Validate published direct-original artifacts and collect their recorded times.

This performs structural/hash validation, not cryptographic proof verification.
Stage durations retain their full paths; parents and children are never summed.
All proving artifacts are read-only. Only the analysis output is written.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import struct


SCHEMA = "stwo-riscv-direct-originals-block-v1"
PHASES = ("admission_ns", "material_ns", "key_ns", "witness_ns",
          "prove_and_serialize_ns", "whole_ns")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, label):
    require(type(value) is int and value >= 0, f"{label}: expected unsigned integer")
    return value


def read_json(path):
    return json.loads(path.read_text())


def file_digest(path):
    require(path.is_file(), f"missing file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    require(size > 0, f"empty file: {path}")
    return size, digest.hexdigest()


def validate_catalog(catalog, wire, windows):
    records = catalog["records"]
    count = 2 * windows - 1
    require(type(records) is list and len(records) == count <= 4095,
            "catalog record count must be 2*windows-1 and at most4095")
    require(catalog["sources"] == windows and catalog["root"] == count - 1,
            "catalog source count/root mismatch")
    expected = bytearray(b"R8CFMD02")
    expected.extend(struct.pack("<4I", 2, count, count - 1, windows))
    uses = [0] * count
    spans = []
    depths = []
    for index, record in enumerate(records):
        require(set(record) == {"kind", "a", "b"}, f"node{index}: unexpected record fields")
        kind, left, right = (uint(record[key], f"node{index}.{key}") for key in ("kind", "a", "b"))
        require(max(kind, left, right) <= 0xffffffff, "record integer overflow")
        expected.extend(struct.pack("<4I", kind, left, right, 0))
        if index < windows:
            require((kind, left, right) == (3, index, 0), "sources must appear once in ordered original-only prefix")
            spans.append((index, 1))
            depths.append(0)
        else:
            require(kind == 2 and left < index and right < index and left != right,
                    f"node{index}: invalid/forward binary edge")
            require(uses[left] == uses[right] == 0, f"node{index}: reused child")
            uses[left] += 1
            uses[right] += 1
            first, length = spans[left]
            require(first + length == spans[right][0], f"node{index}: reordered/nonadjacent source coverage")
            spans.append((first, length + spans[right][1]))
            depths.append(1 + max(depths[left], depths[right]))
            require(depths[-1] <= 16, "catalog depth exceeds native receiving cap")
    require(uses == [1] * (count - 1) + [0], "orphaned/reused catalog node")
    require(spans[-1] == (0, windows), "root does not cover every source")
    require(wire == expected, "catalog.public does not exactly encode catalog.json in canonical binary order")
    return records


def flatten_stages(stages, *, index, filename, prefix="stages", ids=(), labels=()):
    require(type(stages) is list, f"{filename}:{prefix}: expected stage array")
    rows = []
    for ordinal, stage in enumerate(stages):
        path = f"{prefix}[{ordinal}]"
        require(type(stage) is dict, f"{filename}:{path}: expected stage object")
        seconds = stage["seconds"]
        require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0,
                f"{filename}:{path}: invalid duration")
        stage_ids = (*ids, str(stage["id"]))
        stage_labels = (*labels, str(stage["label"]))
        rows.append(dict(index=index, source=filename, path=path + ".seconds",
                         id_path="/".join(stage_ids), label_path="/".join(stage_labels),
                         seconds=seconds, depth=len(ids), aggregation="recorded inclusive duration; do not sum ancestors and descendants"))
        children = stage.get("children")
        if children is not None:
            rows.extend(flatten_stages(children, index=index, filename=filename,
                                       prefix=path + ".children", ids=stage_ids, labels=stage_labels))
    return rows


def collect(directory):
    report = read_json(directory / "report.json")
    require(report["schema"] == SCHEMA and report["proof_verified"] is True,
            "missing successful direct-original driver report")
    for field in ("native_parent_proofs_generated", "legacy_recursive_proofs_read", "legacy_parent_public_metadata_read"):
        require(uint(report[field], field) == 0, f"{field} must be zero")
    require(report["prior_execution_included"] is False and report["prior_original_proving_included"] is False,
            "unexpected timing scope includes historical production")
    windows = uint(report["windows"], "windows")
    require(1 <= windows <= 2048 and report["folds"] == windows - 1, "invalid window/fold counts")
    require(report["original_bundles_reused"] == windows, "original bundle count mismatch")
    catalog = read_json(directory / "catalog.json")
    records = validate_catalog(catalog, (directory / "catalog.public").read_bytes(), windows)
    require(report["root_index"] == catalog["root"], "report root/catalog mismatch")
    expected_files = set()
    rows, stages, artifacts = [], [], []
    for index, record in enumerate(records):
        prefix = f"node-{index}"
        for suffix in ("proof", "timing.json", "statement.json", "stages.json"):
            expected_files.add(f"{prefix}.{suffix}")
        timing_path = directory / f"{prefix}.timing.json"
        timing = read_json(timing_path)
        require(timing["index"] == index and timing["role"] == record["kind"], f"{prefix}: timing identity mismatch")
        is_source = record["kind"] == 3
        require(timing["source_window"] == (record["a"] if is_source else None), f"{prefix}: source identity mismatch")
        require(timing["children"] == ([] if is_source else [record["a"], record["b"]]), f"{prefix}: child order mismatch")
        size, digest = file_digest(directory / f"{prefix}.proof")
        require(size == timing["proof_bytes"] and digest == timing["proof_sha256"], f"{prefix}: proof hash/length mismatch")
        times = {key: uint(timing[key], f"{prefix}.{key}") for key in ("read_ns", "produce_ns", "fresh_verify_ns", "whole_ns")}
        require(times["whole_ns"] == times["read_ns"] + times["produce_ns"] + times["fresh_verify_ns"], f"{prefix}: whole timing mismatch")
        row = dict(index=index, role="original_window" if is_source else "binary_fold",
                   source_window=timing["source_window"], children=",".join(map(str, timing["children"])),
                   proof_bytes=size, proof_sha256=digest, **times,
                   produce_scope=timing["produce_scope"])
        for key, value in times.items():
            row[key.removesuffix("_ns") + "_s"] = value / 1e9
        phases = timing["original_phases"]
        require(is_source == (phases is not None), f"{prefix}: original phase scope mismatch")
        if phases is not None:
            require(set(phases) == set(PHASES), f"{prefix}: unknown/missing Window.Times fields")
            for key in PHASES:
                value = uint(phases[key], f"{prefix}.original_phases.{key}")
                row["window_" + key] = value
                row["window_" + key.removesuffix("_ns") + "_s"] = value / 1e9
        if is_source:
            public_name = f"{prefix}.public"
            expected_files.add(public_name)
            public_size, public_sha = file_digest(directory / public_name)
            with (directory / public_name).open("rb") as stream:
                header = stream.read(9)
            require(header[:8] == b"B8WROOT1" and header[8:] in (b"\0", b"\1"), f"{prefix}: missing native/mixed thin metadata")
            row.update(public_bytes=public_size, public_sha256=public_sha)
        statement_path = directory / f"{prefix}.statement.json"
        read_json(statement_path)
        stage_name = f"{prefix}.stages.json"
        stage_report = read_json(directory / stage_name)
        stages.extend(flatten_stages(stage_report["stages"], index=index, filename=stage_name))
        rows.append(row)
    actual_files = {path.name for path in directory.iterdir() if re.fullmatch(r"node-\d+\..+", path.name)}
    require(actual_files == expected_files, f"orphaned/missing node artifacts: {sorted(actual_files ^ expected_files)}")
    root_size, root_sha = file_digest(directory / "root.proof")
    require((root_size, root_sha) == (report["root_bytes"], report["root_sha256"]), "root/report hash mismatch")
    require((root_size, root_sha) == (rows[catalog["root"]]["proof_bytes"], rows[catalog["root"]]["proof_sha256"]), "root/node proof mismatch")
    for filename in sorted(expected_files | {"report.json", "catalog.json", "catalog.public", "root.proof"}):
        size, digest = file_digest(directory / filename)
        artifacts.append(dict(path=filename, bytes=size, sha256=digest))
    summary = dict(schema="stwo-riscv-direct-original-results-v1", validation="structure and SHA256 artifact consistency only",
                   new_cryptographic_verification=False, driver_reported_proof_verified=True,
                   raw_report=str(directory / "report.json"), raw_report_sha256=file_digest(directory / "report.json")[1],
                   timing_scope=report["timing_scope"], windows=windows, folds=windows - 1,
                   records=len(records), root_index=catalog["root"], root_bytes=root_size, root_sha256=root_sha,
                   stage_aggregation="none; inclusive parent and child durations remain separate", artifacts=artifacts)
    return rows, stages, summary


def write_csv(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, help="analysis destination (default: DIRECTORY/analysis)")
    args = parser.parse_args()
    try:
        directory = args.directory.resolve(strict=True)
        rows, stages, summary = collect(directory)
        output = args.output or directory / "analysis"
        output.mkdir(parents=True, exist_ok=True)
        write_csv(output / "nodes.csv", rows)
        write_csv(output / "stages.csv", stages)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError, struct.error) as error:
        parser.exit(1, f"artifact validation failed: {error}\n")
    print(f"validated {len(rows)} nodes; root SHA256 {summary['root_sha256']}; wrote {output}")


if __name__ == "__main__":
    main()
