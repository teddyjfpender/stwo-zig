#!/usr/bin/env python3
"""Run pinned continuous B8 local cohorts plus one late global-memory bundle."""
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
    parser.add_argument("--cohort-cycles", type=int, default=1 << 17)
    parser.add_argument("--sparse-rom", action="store_true", help="require ELF-authenticated sparse ROM in every local proof")
    parser.add_argument("--parallel-local-proofs", type=int, choices=(1, 2), default=1)
    parser.add_argument("--compact", action="store_true", help="require the explicit compact-global protocol and benchmark binary")
    parser.add_argument("--full-execution-boundaries", action="store_true")
    parser.add_argument("--total-cycles", type=int, default=139214856)
    parser.add_argument("--native-profile", choices=("endpoint_v2", "direct_ram_clock_v3_wide"), default="endpoint_v2")
    args = parser.parse_args()
    if args.full_execution_boundaries and (not args.compact or args.total_cycles <= 0):
        parser.error("full execution boundaries require compact RAM and positive total cycles")
    if args.native_profile != "endpoint_v2" and not args.compact:
        parser.error("wide direct native profile requires compact RAM")
    if not 1 <= args.cohort_cycles <= (1 << (24 if args.native_profile == "direct_ram_clock_v3_wide" else 20)):
        parser.error("cohort cycles exceed selected native profile bounds")
    if not 1 <= args.workers <= 64:
        parser.error("workers must be between 1 and 64")
    capture_path = args.snapshots / "capture.json"
    if capture_path.stat().st_size > 1 << 20 or sha(capture_path) != args.capture_sha256:
        raise ValueError("independently selected capture manifest mismatch")
    capture = json.loads(capture_path.read_text())
    checked_bytes(args.bundle / "guest.elf", "guest.elf")
    if capture["elf_sha256"] != PINS["guest.elf"][0]:
        raise ValueError("capture has another ELF")
    if args.full_execution_boundaries:
        checked_bytes(args.bundle / "input.bin", "input.bin")
        checked_bytes(args.bundle / "expected-output.bin", "expected-output.bin")
        if capture["window"]["skip_cycles"] + capture["window"]["cycles"] > args.total_cycles:
            raise ValueError("window exceeds full execution cycle bound")
    manifest = json.loads(args.build_manifest.read_text())
    if sha(args.binary) != manifest["binary_sha256"]:
        raise ValueError("immutable executable/build manifest mismatch")
    if args.destination.exists():
        raise ValueError("destination exists; preserving previous evidence")
    args.destination.mkdir(parents=True)
    shutil.copy2(args.build_manifest, args.destination / "build.json")
    env = {k: v for k, v in os.environ.items() if not k.startswith("STWO_")}
    with tempfile.TemporaryDirectory(prefix="stwo-b8-local-window-") as temporary:
        staging = Path(temporary)
        for name in ("incoming.b7win", "outgoing.b7win"):
            (staging / name).write_bytes(snapshot_bytes(args.snapshots, name))
        env.update({
            "STWO_B8_LOCAL_ENABLE": "1",
            "STWO_B8_LOCAL_ELF": str((args.bundle / "guest.elf").resolve()),
            "STWO_B8_LOCAL_ELF_SHA256": capture["elf_sha256"],
            "STWO_B8_LOCAL_INCOMING": str(staging / "incoming.b7win"),
            "STWO_B8_LOCAL_INCOMING_SHA256": capture["incoming_sha256"],
            "STWO_B8_LOCAL_OUTGOING": str(staging / "outgoing.b7win"),
            "STWO_B8_LOCAL_OUTGOING_SHA256": capture["outgoing_sha256"],
            "STWO_B8_LOCAL_SKIP": str(capture["window"]["skip_cycles"]),
            "STWO_B8_LOCAL_CYCLES": str(capture["window"]["cycles"]),
            "STWO_B8_LOCAL_WORKERS": str(args.workers),
            "STWO_B8_LOCAL_PARALLEL_PROOFS": str(args.parallel_local_proofs),
            "STWO_B8_LOCAL_SPARSE_ROM": "1" if args.sparse_rom else "0",
            "STWO_B8_LOCAL_COHORT_CYCLES": str(args.cohort_cycles),
            "STWO_B8_LOCAL_OUTPUT": str(args.destination.resolve()),
        })
        if args.full_execution_boundaries:
            env.update(STWO_B8_FULL_INPUT=str((args.bundle / "input.bin").resolve()),
                       STWO_B8_EXPECTED_OUTPUT=str((args.bundle / "expected-output.bin").resolve()),
                       STWO_B8_FULL_INPUT_SHA256=PINS["input.bin"][0],
                       STWO_B8_EXPECTED_OUTPUT_SHA256=PINS["expected-output.bin"][0],
                       STWO_B8_TOTAL_CYCLES=str(args.total_cycles))
        invocation = dict(schema="stwo-b8-pinned-local-pipeline-invocation-v1", capture_sha256=args.capture_sha256,
                          binary_sha256=manifest["binary_sha256"], build_manifest_sha256=sha(args.build_manifest),
                          window=capture["window"], elf_sha256=capture["elf_sha256"],
                          incoming_sha256=capture["incoming_sha256"], outgoing_sha256=capture["outgoing_sha256"],
                          workers=args.workers, parallel_local_proofs=args.parallel_local_proofs, sparse_rom=args.sparse_rom, cohort_cycles=args.cohort_cycles, compact=args.compact, native_profile=args.native_profile, full_execution_boundaries=args.full_execution_boundaries, total_cycles=args.total_cycles if args.full_execution_boundaries else None, cpu_only=True, ethereum_block=False, skipped_prefix_proved=False,
                          recursive_root=False, command=["/usr/bin/time", "-l", str(args.binary.resolve())],
                          started_unix_ns=time.time_ns(), report_checked=False)
        invocation_path = args.destination / "invocation.json"
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
        with (args.destination / "qualification.log").open("wb") as log:
            completed = subprocess.run(invocation["command"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
        invocation.update(returncode=completed.returncode, finished_unix_ns=time.time_ns())
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
        if completed.returncode:
            return completed.returncode
        report = json.loads((args.destination / "report.json").read_text())
        schema = ("stwo-b8-direct-ram-clock-v3-wide-compact-global-pipeline-benchmark-v4" if args.native_profile == "direct_ram_clock_v3_wide" else "stwo-b8-local-endpoint-compact-global-pipeline-benchmark-v1" if args.compact else "stwo-b8-local-endpoint-global-pipeline-benchmark-v1")
        if report.get("schema") != schema or report.get("window") != capture["window"]:
            raise ValueError("incorrect local/global pipeline measurement scope")
        if args.full_execution_boundaries:
            first = capture["window"]["skip_cycles"] == 0
            last = capture["window"]["skip_cycles"] + capture["window"]["cycles"] == args.total_cycles
            if report.get("full_boundary_digest") is None or report.get("initial_boundary") != first or report.get("terminal_boundary") != last:
                raise ValueError("full execution boundary mode mismatch")
        if report.get("security_queries") != 70 or report.get("security_pow_bits") != 26 or report.get("workers") != args.workers:
            raise ValueError("incorrect security or CPU worker budget")
        if args.sparse_rom and report.get("program_flavor") != "sparse_elf":
            raise ValueError("benchmark did not use authenticated sparse ROM")
        if args.parallel_local_proofs != report["stats"].get("parallel_local_proofs", 1):
            raise ValueError("incorrect bounded CPU proof concurrency")
        count = (capture["window"]["cycles"] + args.cohort_cycles - 1) // args.cohort_cycles
        if report.get("layout_version") != (4 if args.native_profile == "direct_ram_clock_v3_wide" else 2) or report["stats"]["cycles"] != capture["window"]["cycles"]:
            raise ValueError("incorrect typed layout or execution census")
        if report.get("cohort_policy") != {"cohort_count": count, "max_cohort_cycles": args.cohort_cycles}:
            raise ValueError("incorrect authenticated global cohort policy")
        if report["verified"]["scope"] != "declared_window_originals_closed" or report["verified"]["cycles"] != capture["window"]["cycles"] or report["verified"]["cohorts"] != count:
            raise ValueError("receiver did not close the exact declared cohort window")
        if report["verified"].get("global_argument") != ("compact_endpoint" if args.compact else "legacy_window"):
            raise ValueError("incorrect global-memory protocol")
        if report["stats"]["cohorts"] != count or report["stats"]["bridge_batches"] != (count + 126) // 127:
            raise ValueError("incorrect exact cohort/bridge count")
        root = args.destination / "artifacts"
        expected = {f"local-{i}.{suffix}" for i in range(count) for suffix in ("proof", "json", "stats.json")}
        expected.update(f"bridge-{i}.proof" for i in range((count + 126) // 127))
        expected.update(("global-memory.proof", "global-public.json"))
        records = report["artifacts"]
        if {entry["name"] for entry in records} != expected or len(records) != len(expected):
            raise ValueError("missing, duplicate or extra proof artifacts")
        for entry in records:
            artifact_path = root / entry["name"]
            if artifact_path.stat().st_size != entry["bytes"] or sha(artifact_path) != entry["sha256"]:
                raise ValueError("artifact bytes differ from the fresh receiver run")
        global_metadata = json.loads((root / "global-public.json").read_text())
        if global_metadata.get("schema") != ("stwo-b8-local-compact-global-memory-metadata-v1" if args.compact else "stwo-b8-local-global-memory-metadata-v1") or global_metadata.get("window") != capture["window"] or global_metadata.get("cohort_policy") != report["cohort_policy"]:
            raise ValueError("incorrect durable global policy metadata")
        for key in ("elf_sha256", "incoming_sha256", "outgoing_sha256"):
            if global_metadata.get(key) != capture[key]:
                raise ValueError("incorrect durable external snapshot/ELF pin")
        for index in range(count):
            if args.sparse_rom:
                local_metadata = json.loads((root / f"local-{index}.json").read_text())
                with (root / f"local-{index}.proof").open("rb") as proof_file:
                    header = proof_file.read(8)
                expected_schema, expected_magic = ("stwo-v8-local-native-endpoint-sparse-rom-direct-ram-clock-wide-v4", b"B8LSW004") if args.native_profile == "direct_ram_clock_v3_wide" else ("stwo-v8-local-native-endpoint-sparse-rom-metadata-v1", b"B8LCS001")
                if local_metadata.get("schema") != expected_schema or header != expected_magic:
                    raise ValueError("local artifact did not use the selected sparse ROM protocol")
            cohort = json.loads((root / f"local-{index}.stats.json").read_text())
            if cohort["security_queries"] != 70 or cohort["security_pow_bits"] != 26 or cohort["cohort_ordinal"] != index or cohort["cohort_count"] != count:
                raise ValueError("incorrect per-cohort security/census")
        invocation["report_checked"] = True
        invocation["report_sha256"] = sha(args.destination / "report.json")
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
    print(json.dumps(dict(destination=str(args.destination), whole_ns=report["whole_including_loading_and_publication_ns"],
                          local_core_proof_ns=report["stats"]["local_core_proof_ns"], charged_peak_bytes=report["stats"]["charged_peak_bytes"], cohorts=report["stats"]["cohorts"], bridge_batches=report["stats"]["bridge_batches"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
