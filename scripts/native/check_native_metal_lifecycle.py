#!/usr/bin/env python3
"""Exercise the installed focused Metal CLI across a process boundary."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def invoke(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"Metal lifecycle command failed: {' '.join(command)}\n{result.stderr}")
    return result.stdout


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_native_metal_lifecycle.py <focused-metal-cli>")
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="stwo-native-metal-lifecycle-") as raw:
        proof = Path(raw) / "proof.json"
        report = json.loads(
            invoke(
                [
                    executable,
                    "prove",
                    "--example",
                    "xor",
                    "--log-size",
                    "8",
                    "--protocol",
                    "smoke",
                    "--proof-artifact-out",
                    str(proof),
                ]
            )
        )
        receipt = json.loads(
            invoke(
                [
                    executable,
                    "verify",
                    "--artifact",
                    str(proof),
                    "--protocol",
                    "smoke",
                ]
            )
        )
    identity = report["product_identity"]
    telemetry = report["backend_telemetry"]
    admission = report["runtime_admission"]
    if report["backend"] != "metal_hybrid" or identity["backend"] != "metal":
        raise SystemExit("focused Metal proof reported the wrong backend identity")
    if identity["aot_manifest"] != "none" or "mode=source-jit" not in identity["runtime_manifest"]:
        raise SystemExit("focused source-JIT product admitted a different runtime identity")
    if telemetry["total_metal_dispatches"] <= 0 or telemetry["total_cpu_fallbacks"] != 0:
        raise SystemExit("focused Metal production proof did not remain device-only")
    if not telemetry["valid"]:
        raise SystemExit("focused Metal production telemetry failed closed")
    platform = admission.get("platform_identity", "")
    for field in ("registry=", "architecture=", "families=", "os-version=", "os-build="):
        if field not in platform:
            raise SystemExit(f"Metal runtime evidence lacks {field}")
    sample = report["proof"]["samples"][0]
    if receipt["status"] != "verified" or receipt["proof_sha256"] != sample["sha256"]:
        raise SystemExit("independent focused Metal verification receipt does not bind the proof")
    if receipt["product"]["identity_sha256"] != identity["identity_sha256"]:
        raise SystemExit("prove and verify processes disagree on exact product identity")
    print("native Metal lifecycle: PASS (device-only prove + independent verify)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
