#!/usr/bin/env python3
"""Consolidate measured original-window gates without implying recursive closure."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()




def peak_rss_bytes(log: str) -> int | None:
    darwin = re.search(r"(\d+)\s+maximum resident set size", log)
    if darwin:
        return int(darwin[1])
    linux = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", log)
    return int(linux[1]) * 1024 if linux else None


def recursive_rows(base: Path, corpus: dict, builds: dict) -> list[dict]:
    """Keep root observations separate from original-set timings."""
    rows = []
    parent_stages = []
    # Resource/partition variants need not encode their proof scope in a
    # directory suffix. The checked report and saved proof decide scope.
    for folder in sorted(base.iterdir()):
        if not (folder / "report.json").is_file():
            continue
        report = json.loads((folder / "report.json").read_text())
        if report.get("scope") != "declared_nonterminal_window_to_complete_recursive_root":
            continue
        invocation = json.loads((folder / "invocation.json").read_text())
        if invocation["returncode"] != 0:
            continue
        build = builds[invocation["build_manifest_sha256"]]
        if invocation["binary_sha256"] != build["binary_sha256"]:
            raise ValueError("recursive root binary does not match build")
        case = next(c for c in corpus["cases"] if c["capture_manifest_sha256"] == invocation["capture_sha256"])
        for key in ("incoming_sha256", "outgoing_sha256", "elf_sha256"):
            if report[key] != case[key]:
                raise ValueError("recursive root input mismatch: " + key)
        if report["cycles"] != case["window"]["cycles"] or report["skip_cycles"] != case["window"]["skip_cycles"]:
            raise ValueError("recursive root endpoint mismatch")
        if not all(report[key] for key in ("verified", "originals_destroyed", "complete_global_closure", "canonical_security")):
            raise ValueError("incomplete recursive root qualification")
        proof = folder / "root.proof"
        if digest(proof) != report["root_sha256"] or proof.stat().st_size != report["root_bytes"]:
            raise ValueError("saved recursive proof mismatch")
        row = {key: value for key, value in report.items() if not isinstance(value, (dict, list))}
        row.update(case=folder.name, input_case=case["case"], binary_sha256=build["binary_sha256"],
                   source_sha256=build.get("source_sha256"), capture_sha256=case["capture_manifest_sha256"],
                   report_sha256=digest(folder / "report.json"), log_sha256=digest(folder / "qualification.log"))
        row["source_excluding_consumer_ns"] = report["source"]["whole_ns"] - report["source"]["consumer_ns"]
        row["original_proof_count"] = report["source"]["original_proofs"]
        row["logical_checkpoint_write_bytes"] = report["source"]["checkpoint_bytes"]
        row["logical_checkpoint_read_bytes"] = None
        row["physical_disk_bytes"] = None
        recursive = report.get("recursive") or report.get("recursive_shared") or report.get("recursive_bounded") or {}
        for key, value in recursive.items():
            if not isinstance(value, (dict, list)):
                row["recursive_" + key] = value
        for key, value in report["source"].items():
            if not isinstance(value, (dict, list)):
                row["source_" + key] = value
        rows.append(row)
        profiles = []
        prefix = "BLAKE3_PARENT_STAGE_PROFILE "
        for line in (folder / "qualification.log").read_text().splitlines():
            if not line.startswith(prefix):
                continue
            profile = json.loads(line[len(prefix):])
            profiles.append(profile)
            def visit(nodes, parent=""):
                for index, node in enumerate(nodes):
                    path = f"{parent}/{index}:{node['id']}"
                    parent_stages.append(dict(case=folder.name, path=path,
                                              parent_path=parent, stage=node["id"],
                                              seconds_inclusive=node["seconds"]))
                    visit(node.get("children") or [], path)
            visit(profile["stages"])
        if profiles:
            (folder / "parent-stage-profile.json").write_text(json.dumps(profiles, indent=2) + "\n")
        case["new_v7_recursive_root_qualified"] = True
        case["recursive_qualification"] = {"directory": str(folder), "scope": report["scope"],
                                           "report_sha256": row["report_sha256"], "root_sha256": report["root_sha256"]}
    if rows:
        with (base / "recursive-window-times.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, list(dict.fromkeys(k for row in rows for k in row)))
            writer.writeheader()
            writer.writerows(rows)
    if parent_stages:
        with (base / "recursive-parent-stages.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, list(parent_stages[0]))
            writer.writeheader()
            writer.writerows(parent_stages)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    base = args.report_dir
    corpus = json.loads((base / "prepared-corpus.json").read_text())
    builds = {digest(path): json.loads(path.read_text()) for path in list(base.glob("*/build.json")) + list(base.glob("*/build-invocation.json"))}
    rows, stages, artifacts = [], [], []
    observations = [(case, base / (case["case"] + "-qualified"), case["case"]) for case in corpus["cases"]]
    by_capture = {case["capture_manifest_sha256"]: case for case in corpus["cases"]}
    for folder in sorted(set(base.glob("*-cut*-w*")) | set(base.glob("features-*-w*"))):
        if not (folder / "invocation.json").is_file():
            continue
        variant = json.loads((folder / "invocation.json").read_text())
        case = by_capture[variant["capture_sha256"]]
        observations.append((case, folder, folder.name))
    for case, folder, name in observations:
        if not (folder / "invocation.json").is_file():
            continue
        invocation = json.loads((folder / "invocation.json").read_text())
        build = builds[invocation["build_manifest_sha256"]]
        if invocation["capture_sha256"] != case["capture_manifest_sha256"] or invocation["binary_sha256"] != build["binary_sha256"]:
            raise ValueError(f"{name}: mismatched selected capture or binary")
        log = (folder / "qualification.log").read_text(errors="replace")
        rss = peak_rss_bytes(log)
        row = {"case": name, "input_case": case["case"], "status": "failed", "scope": "declared_window_original_set", "recursive_root_qualified": False,
               "cycles": case["window"]["cycles"], "skip_cycles": case["window"]["skip_cycles"],
               "capture_sha256": case["capture_manifest_sha256"], "incoming_sha256": case["incoming_sha256"],
               "outgoing_sha256": case["outgoing_sha256"], "elf_sha256": case["elf_sha256"],
               "binary_sha256": build["binary_sha256"], "source_sha256": build["source_sha256"],
               "rss_bytes": rss, "physical_disk_bytes": None,
               "exit_code": invocation["returncode"], "log_sha256": digest(folder / "qualification.log")}
        if invocation["returncode"] == 0:
            report = json.loads((folder / "report.json").read_text())
            if report["window"] != case["window"] or any(report[key] != case[key] for key in ("incoming_sha256", "outgoing_sha256", "elf_sha256")):
                raise ValueError(f"{name}: report does not describe selected inputs")
            if "0 failed" not in log:
                raise ValueError(f"{name}: missing successful gate result")
            row.update(status="verified", **report["stats"])
            row["logical_checkpoint_write_bytes"] = report["stats"]["checkpoint_bytes"]
            row["logical_checkpoint_read_bytes"] = None  # Not instrumented; do not infer physical reads from writes.
            for key in ("worker_count", "segment_cycles", "source_loading_ns", "whole_request_ns", "logical_input_bytes", "host_budget_bytes"):
                row[key] = report[key]
            row.update(report["artifacts"])
            row["native_layout_mode"] = report.get("native_layout_mode", "canonical_v1")
            row["sparse_window_initialization"] = report.get("sparse_window_initialization", False)
            row["resident_memory"] = report.get("resident_memory", False)
            row["native_main_cache_mib"] = report.get("native_main_cache_mib", 256)
            row["deep_group_mib"] = report.get("deep_group_mib", 1)
            proofs = sorted(folder.glob("original-*.postcard"), key=lambda p: int(p.stem.removeprefix("original-")))
            details = [{"name": p.name, "bytes": p.stat().st_size, "sha256": digest(p)} for p in proofs]
            if len(details) != row["proof_count"] or sum(p["bytes"] for p in details) != row["proof_bytes"]:
                raise ValueError(f"{name}: saved original proof roster mismatch")
            row["proof_roster_sha256"] = hashlib.sha256(json.dumps(details, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            artifacts.append({"case": name, "proofs": details, "report_sha256": digest(folder / "report.json"), "profile_sha256": digest(folder / "native-stage-profile.json"), "selection_sha256": digest(folder / "initialization-selection.json") if (folder / "initialization-selection.json").is_file() else None})
            profile = json.loads((folder / "native-stage-profile.json").read_text())
            def visit(node: dict, native_index: int, parent: str) -> None:
                path = parent + "/" + node["id"] if parent else node["id"]
                stages.append({"case": name, "native_index": native_index, "path": path, "seconds_inclusive": node["seconds"], "parent_path": parent})
                for child in node.get("children") or []:
                    visit(child, native_index, path)
            for index, node in enumerate(profile["stages"]):
                visit(node, index, "")
            case["new_v7_original_proof_qualified"] = True
        rows.append(row)
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with (base / "original-window-times.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fields)
        writer.writeheader()
        writer.writerows(rows)
    with (base / "native-core-stages.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, ["case", "native_index", "path", "seconds_inclusive", "parent_path"])
        writer.writeheader()
        writer.writerows(stages)
    (base / "original-window-artifacts.json").write_text(json.dumps({"scope": "original proof sets, not recursive roots; all parent stage times are inclusive", "cases": artifacts}, indent=2) + "\n")
    recursive_rows(base, corpus, builds)
    (base / "prepared-corpus.json").write_text(json.dumps(corpus, indent=2) + "\n")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
