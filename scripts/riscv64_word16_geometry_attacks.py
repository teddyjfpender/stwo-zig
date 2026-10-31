#!/usr/bin/env python3
"""Exercise declaration binding through the actual fresh Ethereum receiver.

Proof files are hard-linked read-only by convention; only NEW bundle files change.
"""
import argparse
import copy
import json
import os
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("config", type=Path)
    parser.add_argument("control", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    metadata = json.loads((args.control / "bundle.json").read_text())
    args.output.mkdir()
    cases = []
    cpu = copy.deepcopy(metadata)
    cpu["cpus"][0]["declaration"]["geometry"]["alu_log"] += 1
    cases.append(("valid_changed_cpu_geometry", cpu, "GlobalExecutionInventoryMismatch"))
    truth = copy.deepcopy(metadata)
    truth["truths"][0]["declaration"]["logs"][0] += 1
    cases.append(("valid_changed_truth_geometry", truth, "GlobalExecutionInventoryMismatch"))
    epoch = copy.deepcopy(metadata)
    epoch["cpus"][0]["request"]["epoch"] += 1
    cases.append(("changed_cpu_epoch", epoch, "InvalidServicesWireRequest"))
    results = []
    for name, mutated, expected in cases:
        directory = args.output / name
        directory.mkdir()
        for source in args.control.glob("*.bin"):
            os.link(source, directory / source.name)
        (directory / "bundle.json").write_text(json.dumps(mutated, indent=2) + "\n")
        command = [str(args.binary.resolve()), "verify", str(args.config.resolve()), str(directory.resolve())]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        (directory / "receiver.stdout").write_text(result.stdout)
        (directory / "receiver.stderr").write_text(result.stderr)
        if result.returncode <= 0 or f"error: {expected}" not in result.stderr:
            raise RuntimeError(f"{name}: expected explicit {expected}, got {result.returncode}: {result.stderr}")
        results.append({"case": name, "exit_code": result.returncode, "rejected_with": expected})
    (args.output / "report.json").write_text(json.dumps({"schema": 1, "scope": "actual fresh receiver; bounded changed geometry is not silently rekeyed", "results": results}, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
