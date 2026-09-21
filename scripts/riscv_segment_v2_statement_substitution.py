#!/usr/bin/env python3
"""Freshly verify a retained tree, then reject independently pinned alternate statements.

Runs two verifier calls per node; does not repeat the full malformed-proof suite.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
from riscv_segment_v2_detached_gate import sha256
from riscv_segment_v2_detached_parent_gate import digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("admission", "other-inputs", "leaf-verifier", "parent-verifier"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", type=digest, required=True)
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("output must be new")
    pins = {}

    def admit(path, pin):
        path = Path(path).resolve()
        if sha256(path) != pin:
            raise ValueError(f"independent input pin mismatch: {path}")
        pins[str(path)] = pin
        return path

    for name in ("admission", "other_inputs", "leaf_verifier", "parent_verifier"):
        setattr(args, name, admit(getattr(args, name), getattr(args, name + "_sha256")))
    original = json.loads(args.admission.read_bytes())
    other = json.loads(args.other_inputs.read_bytes())
    count = len(original["leaves"])
    if (count not in (1, 2, 4, 8) or count != len(other["leaf_expected"])
            or len(original["parents"]) != len(other["parents"])
            or original["profile"] != other["profile"]
            or original.get("memory_addresses", 1) != other["memory_addresses"]
            or original["initial_memory_word"] == other["initial_memory_word"]):
        raise ValueError("substitution must retain workload geometry with a distinct memory seed")
    nodes = []
    for index, (node, expected) in enumerate(zip(original["leaves"], other["leaf_expected"], strict=True)):
        nodes.append((f"leaf-{index}", args.tree / "leaves" / f"child-{index}", args.leaf_verifier,
                      node, expected, ["--root"] if count == 1 else []))
    for depth, (level, alternate) in enumerate(zip(original["parents"], other["parents"], strict=True)):
        if len(level) != len(alternate):
            raise ValueError("parent level geometry differs")
        for index, (node, changed) in enumerate(zip(level, alternate, strict=True)):
            if depth == 0:
                left, right = node["boundary_profile"], changed["boundary_profile"]
                if left["sha256"] != right["sha256"]:
                    raise ValueError("alternate workload has different parent boundary topology")
                admit(args.admission.parent / left["path"], left["sha256"])
                admit(args.other_inputs.parent / right["path"], right["sha256"])
            nodes.append((f"parent-{depth+1}-{index}", args.tree / f"parent-{depth+1}-{index}",
                          args.parent_verifier, node, changed["expected"], []))
    prepared = []
    for name, bundle, verifier, node, alternate, options in nodes:
        expected = admit(args.admission.parent / node["expected"]["path"], node["expected"]["sha256"])
        changed = admit(args.other_inputs.parent / alternate["path"], alternate["sha256"])
        if expected.read_bytes() == changed.read_bytes() or len(json.loads(expected.read_bytes())) != len(json.loads(changed.read_bytes())):
            raise ValueError("expected statements must be distinct with matching wire length")
        admit(bundle / "key.json", node["key"]["sha256"])
        for file in ("claims.json", "proof.bin"):
            path = (bundle / file).resolve()
            pins[str(path)] = sha256(path)
        prepared.append((name, bundle, verifier, node, expected, changed, options))
    report = {"passed": False, "cases": [], "script_sha256": sha256(Path(__file__)), "inputs": pins}
    try:
        for name, bundle, verifier, node, expected, changed, options in prepared:
            for accept, statement in ((True, expected), (False, changed)):
                argv = [str(verifier), *options, str(bundle), node["key"]["sha256"], str(statement)]
                start = time.monotonic_ns()
                result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
                case = {"node": name, "expected_acceptance": accept, "argv": argv, "exit_code": result.returncode,
                        "process_ns": time.monotonic_ns()-start, "stdout": result.stdout, "stderr": result.stderr}
                report["cases"].append(case)
                if accept:
                    receipt = json.loads(result.stdout) if result.returncode == 0 else {}
                    if receipt.get("verified") is not True or receipt.get("native_inputs_used") is not False:
                        raise RuntimeError(f"{name}: genuine statement did not verify")
                elif result.returncode <= 0 or not re.search(r"(?m)^error: [A-Za-z][A-Za-z0-9_]*\s*$", result.stderr):
                    raise RuntimeError(f"{name}: alternate statement did not produce a clean verifier rejection")
        if any(sha256(Path(path)) != pin for path, pin in pins.items()):
            raise RuntimeError("an input changed during verification")
        report["passed"] = True
        print(f"passed {len(report['cases'])} focused genuine/substitution checks")
    finally:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
