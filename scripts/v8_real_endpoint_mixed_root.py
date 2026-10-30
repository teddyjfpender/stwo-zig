#!/usr/bin/env python3
"""Verify saved Mixed+Bridge+Compact originals in one canonical recursive root.

This runner never reexecutes the VM or reproves an original. Hash receipts select
immutable input bytes; the executable independently verifies every original.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from v7_real_window_corpus import ROOT, PINS, checked_bytes, snapshot_bytes


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(destination: Path, capture: dict) -> dict:
    report = json.loads((destination / "report.json").read_text())
    if report.get("schema") != "stwo-b8-saved-mixed-single-dag-root-benchmark-v1" or report.get("window") != capture["window"]:
        raise ValueError("wrong mixed root report scope")
    for key, expected in {"queries": 70, "pow_bits": 26, "workers": 8, "cohorts": 1, "mixed_originals": 1, "bridge_originals": 1, "compact_originals": 1, "source_captures": 3, "intermediate_recursive_proofs": 0, "source_reproof_count": 0, "source_execution_count": 0, "fresh_verified": True, "file_only_receiver": True}.items():
        if report.get(key) != expected:
            raise ValueError(f"wrong {key} in mixed root report")
    root = destination / "root.proof"
    if root.stat().st_size != report["root_bytes"] or sha(root) != report["root_sha256"]:
        raise ValueError("saved root differs from freshly verified proof")
    for name in ("local-0.json", "physical-claims.bin"):
        if not (destination / name).is_file() or (destination / name).stat().st_size == 0:
            raise ValueError("missing durable root input " + name)
    for key in ("source_loading_ns", "late_source_preparation_ns", "profile_ns", "original_verification_ns", "claims_encoding_ns", "whole_ns"):
        if not isinstance(report["source_preparation"].get(key), int) or report["source_preparation"][key] < 0:
            raise ValueError("missing source preparation phase " + key)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "snapshots", "originals", "binary", "build-manifest", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--capture-sha256", required=True)
    parser.add_argument("--source-workers", type=int, default=2, choices=range(1, 5))
    parser.add_argument("--full-execution-boundaries", action="store_true")
    parser.add_argument("--validate-only", action="store_true", help="publish a completed successful run without proving again")
    parser.add_argument("--total-cycles", type=int, default=139214856)
    args = parser.parse_args()
    cap = args.snapshots / "capture.json"
    if cap.stat().st_size > 1 << 20 or sha(cap) != args.capture_sha256:
        raise ValueError("independently selected capture mismatch")
    capture = json.loads(cap.read_text())
    checked_bytes(args.bundle / "guest.elf", "guest.elf")
    if capture["elf_sha256"] != PINS["guest.elf"][0]:
        raise ValueError("wrong guest ELF")
    manifest = json.loads(args.build_manifest.read_text())
    if sha(args.binary) != manifest["binary_sha256"] or manifest.get("exit_code") != 0 or not manifest.get("snapshot_unchanged_after_build") or manifest.get("env_off_smoke_exit_code") != 0:
        raise ValueError("frozen benchmark/build integrity mismatch")
    public = json.loads((args.originals / "global-public.json").read_text())
    if public["window"] != capture["window"] or public["cohort_count"] != 1:
        raise ValueError("wrong original bundle window")
    for key in ("elf_sha256", "incoming_sha256", "outgoing_sha256"):
        if public[key] != capture[key]:
            raise ValueError("wrong original bundle external pin " + key)
    inputs = {}
    for name, magic in {"local-0.json": None, "local-0.proof": b"B8MIS001", "bridge-0.proof": b"B8GBR001", "global-memory.proof": b"B8CMR001", "global-public.json": None}.items():
        path = args.originals / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError("missing original artifact " + name)
        if magic:
            with path.open("rb") as proof:
                if proof.read(8) != magic:
                    raise ValueError("wrong original family " + name)
        inputs[name] = {"sha256": sha(path), "bytes": path.stat().st_size}
    if args.validate_only:
        inv = args.destination / "invocation.json"
        invocation = json.loads(inv.read_text())
        if invocation.get("returncode") != 0 or invocation.get("binary_sha256") != sha(args.binary) or invocation.get("capture_sha256") != args.capture_sha256 or invocation.get("input_artifacts") != inputs:
            raise ValueError("completed invocation does not match these pinned inputs")
        report = validate(args.destination, capture)
        invocation.update(report_checked=True, report_sha256=sha(args.destination / "report.json"), root_sha256=sha(args.destination / "root.proof"), physical_claims_sha256=sha(args.destination / "physical-claims.bin"), metadata_sha256=sha(args.destination / "local-0.json"), global_ram_closed=True, recursive_root=True, publication_validation_runner_sha256=sha(Path(__file__)))
        inv.write_text(json.dumps(invocation, indent=2) + "\n")
        print(json.dumps(dict(destination=str(args.destination), recursive_root=True, report_checked=True, prover_executed=False)))
        return 0
    if args.destination.exists():
        raise ValueError("destination exists; preserving earlier evidence")
    args.destination.mkdir(parents=True)
    shutil.copy2(args.build_manifest, args.destination / "build.json")
    shutil.copy2(cap, args.destination / "capture.json")
    shutil.copy2(args.originals / "global-public.json", args.destination / "global-public.json")
    env = {key: value for key, value in os.environ.items() if not key.startswith("STWO_")}
    invocation = dict(schema="stwo-b8-real-mixed-single-root-invocation-v1", binary_sha256=sha(args.binary), build_manifest_sha256=sha(args.build_manifest), runner_sha256=sha(Path(__file__)), capture_sha256=args.capture_sha256, window=capture["window"], input_census=capture.get("stats", {}), endpoint_events=public.get("endpoint_events"), input_artifacts=inputs, source_workers=args.source_workers, cpu_only=True, source_execution_count=0, source_reproof_count=0, global_ram_closed=False, recursive_root=False, ethereum_block=False, skipped_prefix_proved=False, timing_isolated=False, report_checked=False)
    with tempfile.TemporaryDirectory(prefix="stwo-b8-mixed-root-input-") as temporary:
        staging = Path(temporary)
        for name in ("incoming.b7win", "outgoing.b7win"):
            (staging / name).write_bytes(snapshot_bytes(args.snapshots, name))
        settings = {"SOURCE_DIR": str(args.originals.resolve()), "OUTPUT": str(args.destination.resolve()), "ELF": str((args.bundle / "guest.elf").resolve()), "ELF_SHA256": capture["elf_sha256"], "INCOMING": str(staging / "incoming.b7win"), "OUTGOING": str(staging / "outgoing.b7win"), "INCOMING_SHA256": capture["incoming_sha256"], "OUTGOING_SHA256": capture["outgoing_sha256"], "SKIP": str(capture["window"]["skip_cycles"]), "CYCLES": str(capture["window"]["cycles"]), "SOURCE_WORKERS": str(args.source_workers)}
        if args.full_execution_boundaries:
            checked_bytes(args.bundle / "input.bin", "input.bin")
            output = checked_bytes(args.bundle / "expected-output.bin", "expected-output.bin")
            if len(output) != 43 or args.total_cycles <= 0:
                raise ValueError("invalid full execution boundary")
            settings.update(FULL_INPUT=str((args.bundle / "input.bin").resolve()), FULL_INPUT_SHA256=PINS["input.bin"][0], TOTAL_CYCLES=str(args.total_cycles), EXPECTED_OUTPUT=output.hex())
        env.update({"STWO_B8_JOIN_" + key: value for key, value in settings.items()})
        command = ["/usr/bin/time", "-l", str(args.binary.resolve())]
        invocation.update(command=command, started_unix_ns=time.time_ns())
        inv = args.destination / "invocation.json"
        inv.write_text(json.dumps(invocation, indent=2) + "\n")
        with (args.destination / "qualification.log").open("wb") as log:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
        invocation.update(returncode=result.returncode, finished_unix_ns=time.time_ns())
        inv.write_text(json.dumps(invocation, indent=2) + "\n")
        if result.returncode:
            return result.returncode
        report = validate(args.destination, capture)
        for name, selected in inputs.items():
            if sha(args.originals / name) != selected["sha256"]:
                raise ValueError("original bytes changed during recursive proving")
        invocation.update(report_checked=True, report_sha256=sha(args.destination / "report.json"), root_sha256=sha(args.destination / "root.proof"), physical_claims_sha256=sha(args.destination / "physical-claims.bin"), metadata_sha256=sha(args.destination / "local-0.json"), global_ram_closed=True, recursive_root=True)
        inv.write_text(json.dumps(invocation, indent=2) + "\n")
        print(json.dumps(dict(destination=str(args.destination), whole_s=report["whole_ns"] / 1e9, parent_core_s=report["parent"]["proof_ns"] / 1e9, fresh_receiver_s=report["fresh_receiver_ns"] / 1e9, peak_bytes=report["charged_peak_bytes"], root_bytes=report["root_bytes"], recursive_root=True, ethereum_block=False)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
