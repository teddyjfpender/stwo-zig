#!/usr/bin/env python3
"""Run pinned Group + same-root bridge + compact global ORIGINAL closure."""
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


def validate_report(args, capture, count, cycles, invocation):
    invocation_path = args.destination / "invocation.json"
    report_path = args.destination / "report.json"
    report = json.loads(report_path.read_text())
    if report.get("schema") != "stwo-b8-group-compact-global-original-bundle-benchmark-v1" or report.get("window") != capture["window"]:
        raise ValueError("wrong complete Group measurement scope")
    if (report.get("security_queries"), report.get("security_pow_bits"), report.get("workers")) != (70, 26, args.workers):
        raise ValueError("wrong security/worker policy")
    expected_profile = "native_wide_v2" if args.native_wide else "compact_v1"
    if report.get("group_profile") != expected_profile or report.get("cohort_cycles") != args.cohort_cycles:
        raise ValueError("wrong explicit Group profile")
    verified, stats = report["verified"], report["stats"]
    source = stats["source"]
    if source.get("batch_native_projections", False) != args.native_batch:
        raise ValueError("wrong private native projection mode")
    if (source["cycles"], source["cohorts"], source["trace_trees"], source["fresh_verification_ns"]) != (cycles, count, 4 * count + 7, 0):
        raise ValueError("incorrect group execution/trace census or redundant self-verification")
    if (verified["scope"], verified["global_argument"], verified["groups"], verified["cohorts"], verified["group_original_verifications"], verified["bridge_batches"], verified["cycles"]) != ("declared_window_originals_closed", "compact_endpoint", 1, count, 1, 1, cycles):
        raise ValueError("receiver failed exact window/group/global closure")
    for key in ("elf_sha256", "incoming_sha256", "outgoing_sha256"):
        observed = verified[key]
        if observed != list(bytes.fromhex(capture[key])) and observed != capture[key] and not (isinstance(observed, str) and observed.encode("utf-8") == bytes.fromhex(capture[key])):
            raise ValueError("incorrect fresh external context")
    root = args.destination / "artifacts"
    expected = {"group-0.proof", "group-0.json", "bridge-0.proof", "global-memory.proof", "global-public.json"}
    records = report["artifacts"]
    if {entry["name"] for entry in records} != expected or len(records) != len(expected):
        raise ValueError("missing, duplicate or extra original artifacts")
    for entry in records:
        path = root / entry["name"]
        if path.stat().st_size != entry["bytes"] or sha(path) != entry["sha256"]:
            raise ValueError("artifact differs from freshly received original bundle")
    metadata = json.loads((root / "group-0.json").read_text())
    schema = "stwo-v8-native-wide-group-endpoint-metadata-v2" if args.native_wide else "stwo-v8-group-native-caller-endpoint-metadata-v1"
    if metadata.get("schema") != schema or metadata.get("rom_flavor") != "sparse_elf" or len(metadata["members"]) != count:
        raise ValueError("wrong Group public metadata profile")
    with (root / "group-0.proof").open("rb") as proof:
        if proof.read(8) != (b"B8G2S001" if args.native_wide else b"B8GRS001"):
            raise ValueError("wrong Group original envelope")
    for index, member in enumerate(metadata["members"]):
        if member["cohort_ordinal"] != index or member["caller_statement"] is not None:
            raise ValueError("wrong native-only ordered member roster")
    global_metadata = json.loads((root / "global-public.json").read_text())
    if global_metadata["schema"] != "stwo-b8-group-compact-global-memory-metadata-v1" or global_metadata["window"] != capture["window"] or global_metadata["cohort_policy"] != {"cohort_count": count, "max_cohort_cycles": args.cohort_cycles} or global_metadata["group_count"] != 1 or global_metadata["bridge_batches"] != 1 or global_metadata["endpoint_events"] != verified["endpoint_events"]:
        raise ValueError("wrong durable global admission context")
    for key in ("elf_sha256", "incoming_sha256", "outgoing_sha256"):
        if global_metadata[key] != capture[key]:
            raise ValueError("wrong durable external pin")
    artifacts = records
    invocation.update(report_checked=True, artifacts=artifacts, report_sha256=sha(report_path), publication_validation_runner_sha256=sha(Path(__file__)))
    invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
    return stats


def result_summary(destination, stats):
    source = stats["source"]
    return dict(destination=str(destination), whole_s=stats["whole_ns"] / 1e9,
                group_original_s=source["original_ns"] / 1e9,
                group_core_s=source["original"]["core_ns"] / 1e9,
                bridge_s=stats["bridge_ns"] / 1e9, global_s=stats["global_proof_ns"] / 1e9,
                fresh_bundle_s=stats["fresh_bundle_ns"] / 1e9,
                peak_bytes=stats["charged_peak_bytes"], cohorts=source["cohorts"],
                original_proofs=3, global_ram_closed=True, recursive_root=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "snapshots", "binary", "build-manifest", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--capture-sha256", required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--cohort-cycles", type=int, default=1 << 19)
    parser.add_argument("--native-batch", action="store_true", help="prover-only exact-equation projection batching")
    parser.add_argument("--native-wide", action="store_true", help="explicit new native-wide-v2 Group profile, up to 32 members")
    parser.add_argument("--budget-bytes", type=int, default=48 << 30)
    parser.add_argument("--validate-only", action="store_true", help="check completed saved artifacts without executing the prover again")
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
    cap = 32 if args.native_wide else 8
    cycle_cap = 1 << (24 if args.native_wide else 22)
    if not 1 <= count <= cap or not 0 < cycles <= cycle_cap or not 1 << 30 <= args.budget_bytes <= 60 << 30:
        raise ValueError("group count/window/budget exceeds explicitly selected profile")
    for name in ("keccak_calls", "sha_calls", "recovery_calls"):
        if capture.get("stats", {}).get(name, 0):
            raise ValueError("native-only Group execution does not admit caller captures")
    manifest = json.loads(args.build_manifest.read_text())
    if sha(args.binary) != manifest["binary_sha256"] or not manifest.get("source_unchanged_during_build", False):
        raise ValueError("immutable executable/source build manifest mismatch")
    if args.validate_only:
        invocation = json.loads((args.destination / "invocation.json").read_text())
        if invocation.get("returncode") != 0 or invocation.get("binary_sha256") != sha(args.binary) or invocation.get("capture_sha256") != args.capture_sha256 or invocation.get("workers") != args.workers or invocation.get("cohort_cycles") != args.cohort_cycles or invocation.get("group_profile") != ("native_wide_v2" if args.native_wide else "compact_v1") or invocation.get("native_batch", False) != args.native_batch:
            raise ValueError("saved invocation does not match this successful pinned run")
        validate_report(args, capture, count, cycles, invocation)
        print(json.dumps(dict(destination=str(args.destination), report_checked=True, prover_executed=False)))
        return 0
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
        settings["BUDGET_BYTES"] = str(args.budget_bytes)
        env.update({"STWO_B8_GROUP_BUNDLE_" + key: value for key, value in settings.items()})
        if args.native_wide:
            env["STWO_B8_GROUP_BUNDLE_NATIVE_WIDE"] = "1"
        if args.native_batch:
            env["STWO_B8_GROUP_BUNDLE_NATIVE_BATCH"] = "1"
        command = ["/usr/bin/time", "-l", str(args.binary.resolve())]
        invocation = dict(schema="stwo-b8-pinned-group-complete-original-bundle-invocation-v1", command=command,
                          binary_sha256=sha(args.binary), build_manifest_sha256=sha(args.build_manifest),
                          runner_sha256=sha(Path(__file__)), capture_sha256=args.capture_sha256,
                          window=capture["window"], elf_sha256=capture["elf_sha256"],
                          incoming_sha256=capture["incoming_sha256"], outgoing_sha256=capture["outgoing_sha256"],
                          workers=args.workers, cohorts=count, cohort_cycles=args.cohort_cycles,
                          original_proofs=3, group_original_proofs=1, cpu_only=True, global_ram_closed=True,
                          group_profile="native_wide_v2" if args.native_wide else "compact_v1", budget_bytes=args.budget_bytes, native_batch=args.native_batch,
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
        stats = validate_report(args, capture, count, cycles, invocation)
    print(json.dumps(result_summary(args.destination, stats)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
