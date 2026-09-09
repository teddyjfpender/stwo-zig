#!/usr/bin/env python3
"""Check the source-mapped local recursive AIR lemmas and their axiom closure.

This is not a Zig compiler-refinement or proof-system soundness checker. Source
pins make the reviewed equation-to-theorem mapping fail on later source drift.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parent
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from zig_serial_build import DEFAULT_LOCK, build_lock


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-only", action="store_true", help="Check reviewed source pins without invoking Lean")
    parser.add_argument("--report", type=Path, help="Retain command, source and theorem-audit evidence as JSON")
    args = parser.parse_args()
    mapping = json.loads((FORMAL / "recursive-air-source-map.json").read_text())
    if mapping["schema_version"] != 1:
        raise ValueError("unsupported recursive AIR source-map version")
    def verify_sources() -> None:
        for source in mapping["sources"]:
            actual = digest(ROOT / source["path"])
            if actual != source["sha256"]:
                raise ValueError(f"recursive AIR mapping requires review: {source['path']} expected={source['sha256']} actual={actual}")
    verify_sources()
    report = {
        "schema_version": 1,
        "source_map_sha256": digest(FORMAL / "recursive-air-source-map.json"),
        "sources_checked": len(mapping["sources"]),
        "whole_permutation_formally_refined": False,
        "proof_system_soundness": False,
        "commands": [],
    }
    if not args.source_only:
        commands = [
            ["lake", "build", "RiscvRefinement.Recursion.CompactPoseidon", "RiscvRefinement.Recursion.FrameworkBoundary"],
            ["lake", "env", "lean", "RiscvRefinement/Recursion/AxiomAudit.lean"],
        ]
        with build_lock(DEFAULT_LOCK, label="recursive-air-formal-checks"):
            for command in commands:
                start = time.monotonic()
                result = subprocess.run(command, cwd=FORMAL, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
                report["commands"].append({"argv": command, "elapsed_seconds": time.monotonic() - start, "returncode": result.returncode, "output": result.stdout})
                if result.returncode:
                    sys.stderr.write(result.stdout)
                    return result.returncode
        verify_sources()
        if digest(FORMAL / "recursive-air-source-map.json") != report["source_map_sha256"]:
            raise ValueError("recursive AIR source map changed during checking")
        audit = report["commands"][-1]["output"]
        if "RECURSIVE_AIR_CHECKED 10" not in audit:
            raise ValueError("fresh recursive AIR theorem audit did not report all 10 theorems")
        report["public_theorems_checked"] = 10
        report["local_algebra_checked"] = True
    else:
        report["local_algebra_checked"] = False
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "commands"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
