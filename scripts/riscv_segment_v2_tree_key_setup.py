#!/usr/bin/env python3
"""Derive parent keys from pinned workload statements and independently set-up leaf keys.

Creates and freshly verifies only the child proofs needed for parent key setup.
The final parent key is emitted without creating a candidate root proof.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from riscv_segment_v2_detached_gate import sha256, require_producer_lifecycle
from riscv_segment_v2_detached_parent_gate import digest
from zig_serial_build import build_lock


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--inputs-sha256", type=digest, required=True)
    parser.add_argument("--leaf-keys", type=Path, required=True)
    parser.add_argument("--leaf-keys-receipt-sha256", type=digest, required=True)
    parser.add_argument("--output", type=Path, required=True)
    for role in ("leaf-producer", "leaf-verifier", "parent-producer", "parent-verifier"):
        parser.add_argument("--" + role, type=Path, required=True)
        parser.add_argument("--" + role + "-sha256", type=digest, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error("output must be a new directory")
    admitted = {}

    def admit(path: Path, pin: str) -> Path:
        path = path.resolve()
        if path.is_relative_to(output) or sha256(path) != pin:
            raise ValueError(f"independent input pin mismatch: {path}")
        admitted[str(path)] = pin
        return path

    source = admit(args.inputs, args.inputs_sha256)
    inputs = json.loads(source.read_bytes())
    receipt = json.loads(admit(args.leaf_keys / "setup.json", args.leaf_keys_receipt_sha256).read_bytes())
    count = len(inputs["leaf_expected"])
    if (inputs["version"] != 1 or count not in (1, 2, 4, 8)
            or inputs["profile"] not in ("development_q3_v1", "recursive_q193_v1")
            or type(inputs["memory_addresses"]) is not int or inputs["memory_addresses"] not in (1, 4, 16)
            or type(inputs["initial_memory_word"]) is not int or not 0 <= inputs["initial_memory_word"] <= 0xffffffff
            or receipt["profile"] != inputs["profile"] or receipt["segments"] != count
            or receipt["outer_proofs_created"] != 0 or len(receipt["keys"]) != count):
        raise ValueError("unsupported workload or leaf-key setup receipt")
    levels = inputs["parents"]
    if len(levels) != count.bit_length() - 1 or any(len(level) != count >> (i + 1) for i, level in enumerate(levels)):
        raise ValueError("expected a complete balanced tree")
    for role in ("leaf_producer", "leaf_verifier", "parent_producer", "parent_verifier"):
        setattr(args, role, admit(getattr(args, role), getattr(args, role + "_sha256")))

    def artifact(value):
        path = admit(source.parent / value["path"], digest(value["sha256"]))
        return {"path": str(path), "sha256": value["sha256"]}

    leaves = []
    for index, (expected, key_receipt) in enumerate(zip(inputs["leaf_expected"], receipt["keys"], strict=True)):
        expected = artifact(expected)
        if bytes(key_receipt["expected_wire_sha256"]).hex() != expected["sha256"]:
            raise ValueError("leaf key setup used another expected statement")
        key_pin = bytes(key_receipt["key_sha256"]).hex()
        key = admit(args.leaf_keys / f"child-{index}-key.json", key_pin)
        leaves.append({"key": {"path": str(key), "sha256": key_pin}, "expected": expected})
    for depth, level in enumerate(levels):
        for node in level:
            node["expected"] = artifact(node["expected"])
            boundary = node.get("boundary_profile")
            if depth == 0 and boundary is None:
                raise ValueError("segment children require an independently pinned boundary profile")
            if boundary is not None:
                if depth != 0:
                    raise ValueError("parent children cannot select a native boundary profile")
                node["boundary_profile"] = artifact(boundary)
            else:
                node.pop("boundary_profile", None)
    output.mkdir(parents=True)
    report = {"passed": False, "inputs": admitted, "steps": [], "root_proof_created": False,
              "script_sha256": sha256(Path(__file__)), "segments": count}
    scripts = Path(__file__).resolve().parent

    def run(name, argv, heavy=False):
        argv = [str(value) for value in argv]
        log = output / (name + ".log")
        start = time.monotonic_ns()
        with log.open("x") as stream:
            if heavy:
                with build_lock(label="recursive-tree-key-setup"):
                    result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=600)
            else:
                result = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        report["steps"].append({"name": name, "argv": argv, "exit_code": result.returncode,
                                "elapsed_ns": time.monotonic_ns() - start, "log_sha256": sha256(log)})
        if result.returncode:
            raise RuntimeError(f"{name} failed; retained log: {log}")
        print(f"{name}: passed", flush=True)
        return log

    def child_args(directory, node):
        return [directory, node["key"]["sha256"], node["expected"]["path"]]

    try:
        previous = leaves
        directories = [output / "leaves" / f"child-{i}" for i in range(count)]
        if count > 1:
            argv = [args.leaf_producer, "--memory-addresses", inputs["memory_addresses"],
                    "--segment-count", count, "--initial-memory-word", inputs["initial_memory_word"],
                    "--segments-output", output / "leaves", "--proof-profile", inputs["profile"],
                    "--native-backend", "cpu", "--recursive-backend", "cpu"]
            for index, node in enumerate(leaves):
                argv += [f"--child-{index}-key", node["key"]["path"],
                         f"--child-{index}-key-sha256", node["key"]["sha256"]]
            log = run("produce-leaves", argv, True)
            require_producer_lifecycle(log.read_text(), "cpu", None, "cpu", count, None)
            for index, node in enumerate(leaves):
                accepted = output / f"leaf-{index}-accepted.json"
                run(f"verify-leaf-{index}", [sys.executable, scripts / "riscv_segment_v2_detached_gate.py",
                    "--proof-profile", inputs["profile"], "--verifier", args.leaf_verifier,
                    "--bundle", directories[index], "--key-sha256", node["key"]["sha256"],
                    "--expected-wire", node["expected"]["path"], "--output", accepted])
                if not json.loads(accepted.read_bytes())["passed"]:
                    raise RuntimeError("fresh leaf verification failed")
        for depth, level in enumerate(levels):
            root = depth == len(levels) - 1
            next_dirs = []
            for index, node in enumerate(level):
                name = f"parent-{depth + 1}-{index}"
                key = output / (name + "-key.json")
                profile = ("tiny-parent-root-v2" if root else "tiny-parent-span-v2") if depth else (
                    "tiny-memory-root-v2" if root else "tiny-memory-span-v2" if index == 0 else "tiny-memory-continuation-span-v2")
                children = previous[2 * index:2 * index + 2]
                child_dirs = directories[2 * index:2 * index + 2]
                boundary_args = []
                if "boundary_profile" in node:
                    boundary_args = ["--boundary-profile", node["boundary_profile"]["path"],
                                     "--boundary-profile-sha256", node["boundary_profile"]["sha256"]]
                argv = [args.parent_producer, "derive-key", "--profile", profile, key]
                for directory, child in zip(child_dirs, children, strict=True):
                    argv += child_args(directory, child)
                argv += ["--proof-profile", "recursive_q193_v1" if inputs["profile"] == "recursive_q193_v1" else "detached_continuation_development_q3_v2"] + boundary_args
                run(name + "-setup", argv, True)
                node["key"] = {"path": str(key), "sha256": sha256(key)}
                if root:
                    continue
                bundle, accepted = output / name, output / (name + "-accepted.json")
                argv = [sys.executable, scripts / "riscv_segment_v2_detached_parent_gate.py",
                    "--proof-profile", "recursive_q193_v1" if inputs["profile"] == "recursive_q193_v1" else "detached_continuation_development_q3_v2",
                    "--producer", args.parent_producer, "--producer-sha256", args.parent_producer_sha256,
                    "--verifier", args.parent_verifier, "--verifier-sha256", args.parent_verifier_sha256,
                    "--bundle", bundle, "--parent-key", key, "--key-sha256", node["key"]["sha256"],
                    "--expected-root", node["expected"]["path"], "--expected-root-sha256", node["expected"]["sha256"],
                    "--publication-mode", "intermediate", "--child-family", "parent" if depth else "segment",
                    "--memory-profile", "continuation" if depth == 0 and index > 0 else "initial",
                    "--output", accepted] + boundary_args
                for side, directory, child in zip(("left", "right"), child_dirs, children, strict=True):
                    argv += ["--" + side] + child_args(directory, child)
                run(name + "-qualification", argv)
                if not json.loads(accepted.read_bytes())["passed"]:
                    raise RuntimeError("fresh intermediate verification failed")
                next_dirs.append(bundle)
            previous, directories = level, next_dirs
        if any(sha256(Path(path)) != pin for path, pin in admitted.items()):
            raise RuntimeError("an admitted input changed during setup")
        admission = {key: inputs[key] for key in ("version", "profile", "memory_addresses", "initial_memory_word")}
        admission.update(leaves=leaves, parents=levels)
        for node in leaves + [node for level in levels for node in level]:
            for field in ("key", "expected", "boundary_profile"):
                if field in node:
                    node[field]["path"] = os.path.relpath(node[field]["path"], output)
        target = output / "admission.json"
        target.write_text(json.dumps(admission, indent=2) + "\n")
        report.update(passed=True, admission_sha256=sha256(target),
                      leaf_proofs_created=count if count > 1 else 0, intermediate_proofs_created=max(0, count - 2))
        print(f"ADMISSION {target} {report['admission_sha256']}", flush=True)
    finally:
        (output / "setup.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
