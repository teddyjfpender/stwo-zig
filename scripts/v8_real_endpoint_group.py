#!/usr/bin/env python3
"""Run a pinned native-only bounded Group original. Global RAM/recursion OPEN."""
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "snapshots", "binary", "build-manifest", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--capture-sha256", required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--cohort-cycles", type=int, default=1 << 19)
    args = parser.parse_args()
    if not 1 <= args.workers <= 64 or not 1 <= args.cohort_cycles <= 1 << 20:
        parser.error("workers must be 1..64 and cohort cycles 1..1048576")
    capture_path = args.snapshots / "capture.json"
    if capture_path.stat().st_size > 1 << 20 or sha(capture_path) != args.capture_sha256:
        raise ValueError("independently selected capture manifest mismatch")
    capture = json.loads(capture_path.read_text())
    checked_bytes(args.bundle / "guest.elf", "guest.elf")
    if capture["elf_sha256"] != PINS["guest.elf"][0]:
        raise ValueError("another ELF")
    cycles = capture["window"]["cycles"]
    count = (cycles + args.cohort_cycles - 1) // args.cohort_cycles
    if not 1 <= count <= 8 or not 0 < cycles <= 1 << 22:
        raise ValueError("one bounded group requires 1..8 cohorts and at most 4M cycles")
    for name in ("keccak_calls", "sha_calls", "recovery_calls"):
        if capture.get("stats", {}).get(name, 0):
            raise ValueError("native-only Group execution does not admit caller captures")
    manifest = json.loads(args.build_manifest.read_text())
    if sha(args.binary) != manifest["binary_sha256"] or not manifest.get("source_unchanged_during_build", False):
        raise ValueError("immutable executable/source build manifest mismatch")
    if args.destination.exists():
        raise ValueError("destination exists; preserving previous evidence")
    args.destination.mkdir(parents=True)
    shutil.copy2(args.build_manifest, args.destination / "build.json")
    shutil.copy2(capture_path, args.destination / "capture.json")
    env = {key: value for key, value in os.environ.items() if not key.startswith("STWO_")}
    with tempfile.TemporaryDirectory(prefix="stwo-b8-group-") as temporary:
        staging = Path(temporary)
        for name in ("incoming.b7win", "outgoing.b7win"):
            (staging / name).write_bytes(snapshot_bytes(args.snapshots, name))
        settings = {"ENABLE": "1", "ELF": str((args.bundle / "guest.elf").resolve()),
                    "ELF_SHA256": capture["elf_sha256"], "INCOMING": str(staging / "incoming.b7win"),
                    "OUTGOING": str(staging / "outgoing.b7win"),
                    "INCOMING_SHA256": capture["incoming_sha256"], "OUTGOING_SHA256": capture["outgoing_sha256"],
                    "SKIP": str(capture["window"]["skip_cycles"]), "CYCLES": str(cycles),
                    "COHORT_CYCLES": str(args.cohort_cycles), "WORKERS": str(args.workers),
                    "OUTPUT": str(args.destination.resolve())}
        env.update({"STWO_B8_GROUP_" + key: value for key, value in settings.items()})
        command = ["/usr/bin/time", "-l", str(args.binary.resolve())]
        invocation = dict(schema="stwo-b8-pinned-group-original-invocation-v1", command=command,
                          binary_sha256=sha(args.binary), build_manifest_sha256=sha(args.build_manifest),
                          runner_sha256=sha(Path(__file__)), capture_sha256=args.capture_sha256,
                          window=capture["window"], elf_sha256=capture["elf_sha256"],
                          incoming_sha256=capture["incoming_sha256"], outgoing_sha256=capture["outgoing_sha256"],
                          workers=args.workers, cohorts=count, cohort_cycles=args.cohort_cycles,
                          original_proofs=1, cpu_only=True, global_ram_closed=False,
                          recursive_root=False, ethereum_block=False, skipped_prefix_proved=False,
                          started_unix_ns=time.time_ns(), report_checked=False)
        invocation_path = args.destination / "invocation.json"
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
        with (args.destination / "qualification.log").open("wb") as log:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
        invocation.update(returncode=result.returncode, finished_unix_ns=time.time_ns())
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
        if result.returncode:
            return result.returncode
        report_path = args.destination / "report.json"
        report = json.loads(report_path.read_text())
        if report.get("schema") != "stwo-b8-shared-group-original-benchmark-v1" or report.get("window") != capture["window"]:
            raise ValueError("wrong group measurement scope")
        if (report.get("security_queries"), report.get("security_pow_bits"), report.get("workers"), report.get("verified_once")) != (70, 26, args.workers, True):
            raise ValueError("wrong security/worker/verification policy")
        for key in ("elf_sha256", "incoming_sha256", "outgoing_sha256"):
            if report.get(key) != capture[key]:
                raise ValueError("wrong pinned external context")
        stats = report["stats"]
        if (stats["cycles"], stats["cohorts"], stats["trace_trees"]) != (cycles, count, 4 * count + 7):
            raise ValueError("incorrect group execution/trace census")
        proof_path, metadata_path = (args.destination / name for name in ("group.proof", "group.json"))
        if proof_path.stat().st_size != stats["proof_bytes"] or sha(proof_path) != report["proof_sha256"]:
            raise ValueError("proof bytes differ from measured original")
        with proof_path.open("rb") as proof:
            if proof.read(8) != b"B8GRS001":
                raise ValueError("wrong group original envelope")
        if metadata_path.stat().st_size > 16 << 20:
            raise ValueError("unbounded group metadata")
        metadata = json.loads(metadata_path.read_text())
        if metadata.get("schema") != "stwo-v8-group-native-caller-endpoint-metadata-v1" or metadata.get("rom_flavor") != "sparse_elf":
            raise ValueError("wrong Group public metadata protocol")
        members, sources = metadata["members"], report["endpoint_sources"]
        if len(members) != count or len(sources) != count or metadata["lookup_plan"]["execution_count"] != count:
            raise ValueError("missing/duplicate group source roster")
        for index, (member, source) in enumerate(zip(members, sources, strict=True)):
            if member["cohort_ordinal"] != index or member["caller_statement"] is not None:
                raise ValueError("wrong native-only ordered cohort roster")
            if member["endpoint_count"] != source["endpoint_count"] or member["endpoint_main_root"] != source["endpoint_root"] or member["frame"] != source["frame"]:
                raise ValueError("endpoint metadata differs from freshly verified source")
        artifacts = [{"name": path.name, "bytes": path.stat().st_size, "sha256": sha(path)} for path in (proof_path, metadata_path, report_path)]
        invocation.update(report_checked=True, artifacts=artifacts, report_sha256=sha(report_path))
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
    print(json.dumps(dict(destination=str(args.destination), whole_s=stats["whole_ns"] / 1e9,
                          original_s=stats["original_ns"] / 1e9, core_s=stats["original"]["core_ns"] / 1e9,
                          fresh_verify_s=stats["fresh_verification_ns"] / 1e9,
                          peak_bytes=stats["charged_peak_bytes"], cohorts=count, original_proofs=1,
                          global_ram_closed=False)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
