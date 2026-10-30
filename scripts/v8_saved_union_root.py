#!/usr/bin/env python3
"""Produce a new in-proof-closed V8 window root from a pinned saved original.

This measures saved original -> fresh original verification -> new recursive
proof -> fresh root verification. It does NOT include original source proving,
prove a skipped prefix, or certify complete Ethereum guest completion.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from v7_real_window_corpus import ROOT, PINS, checked_bytes, snapshot_bytes
from v7_real_window_v2 import timed_command


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_report(report: dict, capture: dict, proof_hash: str, metadata_hash: str, workers: int, destination: Path) -> None:
    if report.get("schema") != "stwo-v8-saved-original-closed-root-v1" or report.get("scope") != "saved_canonical_original_to_in_proof_closed_declared_window_root":
        raise ValueError("incorrect V8 theorem or timing boundary")
    for key in ("verified", "canonical_security", "closure_in_proof", "source_original_fresh_verified", "original_proof_objects_destroyed", "original_capture_destroyed", "producer_parent_rows_destroyed", "fresh_metadata_independently_reconstructed"):
        if report.get(key) is not True:
            raise ValueError(f"missing qualification boundary: {key}")
    for key in ("host_global_closure_used_by_root_receiver", "source_proving_performed", "ethereum_block", "skipped_prefix_proved", "terminal"):
        if report.get(key) is not False:
            raise ValueError(f"incorrect claimed scope: {key}")
    if (report.get("query_count"), report.get("pow_bits"), report.get("worker_count"), report.get("source_stark_count"), report.get("recursive_stark_count"), report.get("callers")) != (70, 26, workers, 1, 1, 0):
        raise ValueError("unexpected security/worker/proof roster")
    if report.get("window") != capture["window"]:
        raise ValueError("wrong declared execution window")
    for key in ("elf_sha256", "incoming_sha256", "outgoing_sha256"):
        if report.get(key) != capture[key]:
            raise ValueError(f"incorrect external source: {key}")
    if report.get("source_proof_sha256") != proof_hash or report.get("metadata_sha256") != metadata_hash:
        raise ValueError("saved original artifact identity changed")
    for filename, prefix in (("root.proof", "root"), ("union.claims", "claims")):
        data = (destination / filename).read_bytes()
        if report.get(prefix + "_bytes") != len(data) or report.get(prefix + "_sha256") != sha(data):
            raise ValueError(f"artifact mismatch: {filename}")
    if not isinstance(report.get("whole_request_ns"), int) or report["whole_request_ns"] <= 0:
        raise ValueError("missing request timing")
    if not isinstance(report.get("recursive", {}).get("proof_ns"), int) or report["recursive"]["proof_ns"] <= 0:
        raise ValueError("missing actual STARK phase")


def run(args: argparse.Namespace) -> int:
    capture_bytes = (args.snapshots / "capture.json").read_bytes()
    if len(capture_bytes) > 1 << 20 or sha(capture_bytes) != args.capture_sha256:
        raise ValueError("capture is not the independently selected input")
    capture = json.loads(capture_bytes)
    if capture["elf_sha256"] != PINS["guest.elf"][0]:
        raise ValueError("capture uses a different retained Ethereum ELF")
    checked_bytes(args.bundle / "guest.elf", "guest.elf")
    proof = args.source / "union.proof"
    metadata = args.source / "union-public.json"
    if proof.stat().st_size > 128 << 20 or sha(proof.read_bytes()) != args.source_proof_sha256:
        raise ValueError("saved original proof hash mismatch")
    if metadata.stat().st_size > 16 << 20 or sha(metadata.read_bytes()) != args.metadata_sha256:
        raise ValueError("saved original metadata hash mismatch")
    provenance = json.loads(args.build_manifest.read_text())
    binary_hash = sha(args.binary.read_bytes())
    if provenance["binary_sha256"] != binary_hash:
        raise ValueError("binary differs from the selected frozen build")
    if args.destination.exists():
        raise ValueError("destination exists; preserving previous evidence")
    args.destination.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="stwo-v8-saved-union-") as temporary:
        staging = Path(temporary)
        for name in ("incoming.b7win", "outgoing.b7win"):
            (staging / name).write_bytes(snapshot_bytes(args.snapshots, name))
        env = {key: value for key, value in os.environ.items() if not key.startswith("STWO_")}
        env.update({
            "STWO_V8_SAVED_ELF": str((args.bundle / "guest.elf").resolve()),
            "STWO_V8_SAVED_ELF_SHA256": capture["elf_sha256"],
            "STWO_V8_SAVED_INCOMING": str(staging / "incoming.b7win"),
            "STWO_V8_SAVED_OUTGOING": str(staging / "outgoing.b7win"),
            "STWO_V8_SAVED_INCOMING_SHA256": capture["incoming_sha256"],
            "STWO_V8_SAVED_OUTGOING_SHA256": capture["outgoing_sha256"],
            "STWO_V8_SAVED_SOURCE_PROOF": str(proof.resolve()),
            "STWO_V8_SAVED_SOURCE_PROOF_SHA256": args.source_proof_sha256,
            "STWO_V8_SAVED_METADATA": str(metadata.resolve()),
            "STWO_V8_SAVED_METADATA_SHA256": args.metadata_sha256,
            "STWO_V8_SAVED_SKIP": str(capture["window"]["skip_cycles"]),
            "STWO_V8_SAVED_CYCLES": str(capture["window"]["cycles"]),
            "STWO_V8_SAVED_WORKERS": str(args.workers),
            "STWO_V8_SAVED_OUTPUT": str(args.destination.resolve()),
        })
        command = timed_command(args.binary)
        invocation = dict(schema="stwo-v8-saved-original-closed-root-invocation-v1", scope="saved_original_to_new_closed_recursive_root", command=command,
                          binary_sha256=binary_hash, build_manifest_sha256=sha(args.build_manifest.read_bytes()),
                          capture_sha256=args.capture_sha256, source_proof_sha256=args.source_proof_sha256,
                          metadata_sha256=args.metadata_sha256, source_proving_performed=False, cpu_only=True,
                          started_unix_ns=time.time_ns(), report_checked=False)
        path = args.destination / "invocation.json"
        path.write_text(json.dumps(invocation, indent=2) + "\n")
        with (args.destination / "qualification.log").open("w") as output:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT, check=False)
        invocation.update(returncode=result.returncode, finished_unix_ns=time.time_ns())
        if result.returncode == 0:
            report = json.loads((args.destination / "report.json").read_text())
            validate_report(report, capture, args.source_proof_sha256, args.metadata_sha256, args.workers, args.destination)
            invocation["report_checked"] = True
        path.write_text(json.dumps(invocation, indent=2) + "\n")
        if result.returncode:
            print(f"saved-original V8 root failed; evidence retained in {args.destination}")
        else:
            print(f"qualified saved-original V8 closed root: {args.destination}")
        return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "snapshots", "source", "binary", "build-manifest", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("capture-sha256", "source-proof-sha256", "metadata-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--workers", type=int, default=8, choices=range(1, 65))
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
