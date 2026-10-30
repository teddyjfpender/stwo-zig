#!/usr/bin/env python3
"""Capture larger real windows from a selected capsule without replaying the prefix."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from v7_real_window_corpus import ROOT, PINS, checked_bytes, snapshot_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "snapshots", "binary", "build-manifest", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--capture-sha256", required=True)
    parser.add_argument("--cycles", type=int, required=True)
    args = parser.parse_args()
    if not 0 < args.cycles <= 1 << 23:
        parser.error("cycles must be between 1 and 8388608")
    original = (args.snapshots / "capture.json").read_bytes()
    if len(original) > 1 << 20 or hashlib.sha256(original).hexdigest() != args.capture_sha256:
        raise ValueError("capture manifest does not match the selected hash")
    selected = json.loads(original)
    if selected["elf_sha256"] != PINS["guest.elf"][0]:
        raise ValueError("selected capture has the wrong retained ELF")
    checked_bytes(args.bundle / "guest.elf", "guest.elf")
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if json.loads(args.build_manifest.read_text())["binary_sha256"] != binary_hash:
        raise ValueError("immutable binary build manifest mismatch")
    if args.destination.exists():
        raise ValueError("destination exists; refusing to replace evidence")
    args.destination.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="stwo-window-continuation-") as tmp:
        incoming = Path(tmp) / "incoming.b7win"
        incoming_bytes = snapshot_bytes(args.snapshots, "incoming.b7win")
        incoming.write_bytes(incoming_bytes)
        env = os.environ | {
            "STWO_WINDOW_CONTINUE_ELF": str((args.bundle / "guest.elf").resolve()),
            "STWO_WINDOW_CONTINUE_ELF_SHA256": selected["elf_sha256"],
            "STWO_WINDOW_CONTINUE_INCOMING": str(incoming),
            "STWO_WINDOW_CONTINUE_INCOMING_SHA256": selected["incoming_sha256"],
            "STWO_WINDOW_CONTINUE_CYCLES": str(args.cycles),
            "STWO_WINDOW_CONTINUE_SKIP": str(selected["window"]["skip_cycles"]),
            "STWO_WINDOW_CONTINUE_OUTPUT": str(args.destination.resolve()),
        }
        command = ["/usr/bin/time", "-l", str(args.binary.resolve())]
        invocation = {
            "schema": "stwo-real-window-continuation-invocation-v2",
            "source_capture_sha256": args.capture_sha256,
            "binary_sha256": binary_hash,
            "build_manifest_sha256": hashlib.sha256(args.build_manifest.read_bytes()).hexdigest(),
            "cycles": args.cycles, "prefix_replayed": False, "proof_verified": False,
            "command": command, "started_unix_ns": time.time_ns(),
            "logical_capsule_read_bytes": len(incoming_bytes),
            "temporary_capsule_write_bytes": len(incoming_bytes),
            "physical_disk_bytes": None,
        }
        invocation_path = args.destination / "invocation.json"
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
        with (args.destination / "capture.log").open("wb") as log:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
        invocation.update(returncode=result.returncode, finished_unix_ns=time.time_ns())
        invocation_path.write_text(json.dumps(invocation, indent=2) + "\n")
        if result.returncode == 0:
            if not (args.destination / "capture.json").is_file():
                raise RuntimeError("capture succeeded without endpoint metadata")
            for name in ("incoming.b7win", "outgoing.b7win"):
                path = args.destination / name
                data = path.read_bytes()
                (args.destination / (name + ".gz")).write_bytes(gzip.compress(data, mtime=0))
                path.unlink()
            print(hashlib.sha256((args.destination / "capture.json").read_bytes()).hexdigest())
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
