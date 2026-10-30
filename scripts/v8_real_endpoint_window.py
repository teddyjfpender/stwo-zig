#!/usr/bin/env python3
"""Run one pinned CPU B8 original window; never label it a block or root."""
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
    args = parser.parse_args()
    if not 1 <= args.workers <= 64:
        parser.error("workers must be between 1 and 64")
    capture_path = args.snapshots / "capture.json"
    if capture_path.stat().st_size > 1 << 20 or sha(capture_path) != args.capture_sha256:
        raise ValueError("independently selected capture manifest mismatch")
    capture = json.loads(capture_path.read_text())
    checked_bytes(args.bundle / "guest.elf", "guest.elf")
    if capture["elf_sha256"] != PINS["guest.elf"][0]:
        raise ValueError("capture has another ELF")
    manifest = json.loads(args.build_manifest.read_text())
    if sha(args.binary) != manifest["binary_sha256"]:
        raise ValueError("immutable executable/build manifest mismatch")
    if args.destination.exists():
        raise ValueError("destination exists; preserving previous evidence")
    args.destination.mkdir(parents=True)
    shutil.copy2(args.build_manifest, args.destination / "build.json")
    env = {k: v for k, v in os.environ.items() if not k.startswith("STWO_")}
    with tempfile.TemporaryDirectory(prefix="stwo-b8-pinned-window-") as temporary:
        staging = Path(temporary)
        for name in ("incoming.b7win", "outgoing.b7win"):
            (staging / name).write_bytes(snapshot_bytes(args.snapshots, name))
        env.update({
            "STWO_B8_WINDOW_ENABLE": "1",
            "STWO_B8_WINDOW_ELF": str((args.bundle / "guest.elf").resolve()),
            "STWO_B8_WINDOW_ELF_SHA256": capture["elf_sha256"],
            "STWO_B8_WINDOW_INCOMING": str(staging / "incoming.b7win"),
            "STWO_B8_WINDOW_INCOMING_SHA256": capture["incoming_sha256"],
            "STWO_B8_WINDOW_OUTGOING": str(staging / "outgoing.b7win"),
            "STWO_B8_WINDOW_OUTGOING_SHA256": capture["outgoing_sha256"],
            "STWO_B8_WINDOW_SKIP": str(capture["window"]["skip_cycles"]),
            "STWO_B8_WINDOW_CYCLES": str(capture["window"]["cycles"]),
            "STWO_B8_WINDOW_WORKERS": str(args.workers),
            "STWO_B8_WINDOW_OUTPUT": str(args.destination.resolve()),
        })
        invocation = dict(schema="stwo-b8-pinned-window-invocation-v1", capture_sha256=args.capture_sha256,
                          binary_sha256=manifest["binary_sha256"], build_manifest_sha256=sha(args.build_manifest),
                          window=capture["window"], elf_sha256=capture["elf_sha256"],
                          incoming_sha256=capture["incoming_sha256"], outgoing_sha256=capture["outgoing_sha256"],
                          workers=args.workers, cpu_only=True, ethereum_block=False, skipped_prefix_proved=False,
                          recursive_root=False, command=["/usr/bin/time", "-l", str(args.binary.resolve())],
                          started_unix_ns=time.time_ns(), report_checked=False)
        path = args.destination / "invocation.json"
        path.write_text(json.dumps(invocation, indent=2) + "\n")
        with (args.destination / "qualification.log").open("wb") as log:
            completed = subprocess.run(invocation["command"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
        invocation.update(returncode=completed.returncode, finished_unix_ns=time.time_ns())
        path.write_text(json.dumps(invocation, indent=2) + "\n")
        if completed.returncode:
            return completed.returncode
        report = json.loads((args.destination / "report.json").read_text())
        if report.get("schema") != "stwo-b8-native-endpoint-window-benchmark-v1" or report.get("window") != capture["window"]:
            raise ValueError("incorrect original-window measurement scope")
        if report.get("security_queries") != 70 or report.get("security_pow_bits") != 26 or report.get("workers") != args.workers:
            raise ValueError("incorrect security or CPU worker budget")
        if report.get("layout_version") != 2 or report["stats"]["cycles"] != capture["window"]["cycles"]:
            raise ValueError("incorrect typed layout or execution census")
        if report["verified"]["scope"] != "declared_nonterminal_window" or report["verified"]["cycles"] != capture["window"]["cycles"]:
            raise ValueError("receiver did not verify the declared window")
        if sha(args.destination / "original.proof") != report["proof_sha256"] or sha(args.destination / "public-metadata.json") != report["metadata_sha256"]:
            raise ValueError("artifact bytes no longer match the successful receiver report")
        invocation["report_checked"] = True
        invocation["report_sha256"] = sha(args.destination / "report.json")
        path.write_text(json.dumps(invocation, indent=2) + "\n")
    print(json.dumps(dict(destination=str(args.destination), whole_ns=report["whole_including_loading_and_publication_ns"],
                          core_proof_ns=report["stats"]["original"]["core_proof_ns"], charged_peak_bytes=report["charged_peak_bytes"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
