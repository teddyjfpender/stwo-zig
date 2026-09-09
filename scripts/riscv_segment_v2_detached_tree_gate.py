#!/usr/bin/env python3
"""Prove and independently verify an admitted small 2/4/8-segment tree.

This serial fixture runner owns scheduling and evidence only. The existing Zig
producers/verifiers own execution, AIR, transcript, coverage and continuation.
An independently pinned manifest supplies every key and expected statement.
All native, wrapper and parent proving uses the selected backend. CPU verifies.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from riscv_segment_v2_detached_gate import AOT_PROFILES, require_producer_lifecycle, sha256
from riscv_segment_v2_detached_parent_gate import digest
from zig_serial_build import build_lock


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--admission-sha256", type=digest, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend", choices=("cpu", "metal"), required=True)
    for role in ("leaf-producer", "parent-producer", "leaf-verifier", "parent-verifier"):
        parser.add_argument("--" + role, type=Path, required=True)
        parser.add_argument("--" + role + "-sha256", type=digest, required=True)
    parser.add_argument("--aot-bundle", type=Path)
    parser.add_argument("--aot-manifest-sha256", type=digest)
    parser.add_argument("--aot-profile", choices=tuple(AOT_PROFILES))
    args = parser.parse_args()
    if args.aot_profile is not None and args.backend != "metal":
        parser.error("CPU proving does not accept an AOT profile")
    if (args.backend == "metal") != bool(args.aot_bundle and args.aot_manifest_sha256) or bool(args.aot_bundle) != bool(args.aot_manifest_sha256):
        parser.error("only Metal requires both AOT bundle and manifest pin")
    output = args.output.resolve()
    if output.exists():
        parser.error("output must be new; retain previous proof evidence")
    inputs: dict[Path, str] = {}

    def admit(path: Path, pin: str) -> Path:
        path = path.resolve()
        if path.is_relative_to(output) or sha256(path) != pin:
            raise ValueError(f"independent input pin mismatch: {path}")
        inputs[path] = pin
        return path

    manifest_path = admit(args.admission, args.admission_sha256)
    manifest = json.loads(manifest_path.read_bytes())
    if manifest["version"] != 1 or manifest["profile"] not in ("development_q3_v1", "recursive_q193_v1"):
        raise ValueError("unsupported small-tree admission profile")
    leaves, levels = manifest["leaves"], manifest["parents"]
    count = len(leaves)
    if count not in (2, 4, 8) or len(levels) != count.bit_length() - 1 or any(
            len(level) != count >> (index + 1) for index, level in enumerate(levels)):
        raise ValueError("admission must describe one complete balanced 2/4/8 tree")
    seed = manifest["initial_memory_word"]
    if type(seed) is not int or not 0 <= seed <= 0xffffffff:
        raise ValueError("initial memory word must fit u32")
    for node in leaves + [node for level in levels for node in level]:
        for field in ("key", "expected"):
            value = node[field]
            value["resolved"] = str(admit(manifest_path.parent / value["path"], digest(value["sha256"])))
    for role in ("leaf_producer", "parent_producer", "leaf_verifier", "parent_verifier"):
        setattr(args, role, admit(getattr(args, role), getattr(args, role + "_sha256")))
    if args.aot_bundle:
        admit(args.aot_bundle / "stwo_zig_core.manifest.json", args.aot_manifest_sha256)
    output.mkdir(parents=True)
    report = {"gate_sha256": sha256(Path(__file__)), "admission_sha256": args.admission_sha256,
              "backend": args.backend, "aot_profile": AOT_PROFILES[args.aot_profile or "core-v2"] if args.backend == "metal" else None, "segments": count, "profile": manifest["profile"],
              "inputs": {str(p): pin for p, pin in inputs.items()}, "steps": [], "passed": False,
              "timing_scope": "complete gate includes hostile cases; production sums are separate measurements"}
    scripts = Path(__file__).resolve().parent
    started = time.monotonic_ns()

    def run(name: str, argv: list[str], *, heavy: bool = False) -> dict:
        log = output / (name + ".log")
        entry = {"name": name, "argv": argv, "log": str(log)}
        report["steps"].append(entry)
        def execute() -> None:
            begin = time.monotonic_ns()
            with log.open("xb") as stream:
                process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT)
                try:
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                except BaseException:
                    process.kill()
                    process.wait()
                    raise
            entry.update(exit_code=process.returncode, process_ns=time.monotonic_ns() - begin,
                         maximum_rss_bytes=usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                         log_sha256=sha256(log))
            if process.returncode:
                raise RuntimeError(f"{name} failed; retained log: {log}")
        if heavy:
            with build_lock(label="small-detached-tree"):
                execute()
        else:
            execute()
        return entry

    def child_args(directory: Path, node: dict) -> list[str]:
        return [str(directory), node["key"]["sha256"], node["expected"]["resolved"]]

    try:
        leaf_dir = output / "leaves"
        argv = [str(args.leaf_producer), "--memory-addresses", "1", "--segments-output", str(leaf_dir),
                "--segment-count", str(count), "--initial-memory-word", str(seed),
                "--proof-profile", manifest["profile"], "--native-backend", args.backend,
                "--recursive-backend", args.backend]
        for index, node in enumerate(leaves):
            argv += [f"--child-{index}-key", node["key"]["resolved"],
                     f"--child-{index}-key-sha256", node["key"]["sha256"]]
        if args.backend == "metal":
            argv += ["--aot-bundle", str(args.aot_bundle.resolve()), "--aot-manifest-sha256", args.aot_manifest_sha256]
            if args.aot_profile is not None:
                argv += ["--aot-profile", args.aot_profile]
        batch = run("produce-leaves", argv, heavy=True)
        text = Path(batch["log"]).read_text()
        batch["lifecycle"] = require_producer_lifecycle(
            text, args.backend, args.aot_manifest_sha256, args.backend, count, args.aot_profile)
        previous_dirs = [leaf_dir / f"child-{index}" for index in range(count)]
        for index, (directory, node) in enumerate(zip(previous_dirs, leaves)):
            gate = output / f"leaf-{index}-accepted.json"
            run(f"verify-leaf-{index}", [sys.executable, str(scripts / "riscv_segment_v2_detached_gate.py"),
                "--proof-profile", manifest["profile"], "--verifier", str(args.leaf_verifier),
                "--bundle", str(directory), "--key-sha256", node["key"]["sha256"],
                "--expected-wire", node["expected"]["resolved"], "--output", str(gate)])
            if not json.loads(gate.read_bytes())["passed"]:
                raise RuntimeError("leaf proof gate did not pass")
        previous_nodes = leaves
        parent_production_ns = 0
        for level_index, level in enumerate(levels):
            directories = []
            for index, node in enumerate(level):
                name = f"parent-{level_index + 1}-{index}"
                directory, gate = output / name, output / (name + "-accepted.json")
                root = level_index == len(levels) - 1
                argv = [sys.executable, str(scripts / "riscv_segment_v2_detached_parent_gate.py"),
                        "--proof-profile", "recursive_q193_v1" if manifest["profile"] == "recursive_q193_v1" else "detached_continuation_development_q3_v2",
                        "--verifier", str(args.parent_verifier), "--verifier-sha256", args.parent_verifier_sha256,
                        "--producer", str(args.parent_producer), "--producer-sha256", args.parent_producer_sha256,
                        "--bundle", str(directory), "--parent-key", node["key"]["resolved"], "--key-sha256", node["key"]["sha256"],
                        "--expected-root", node["expected"]["resolved"], "--expected-root-sha256", node["expected"]["sha256"],
                        "--publication-mode", "root" if root else "intermediate", "--child-family", "segment" if level_index == 0 else "parent",
                        "--memory-profile", "continuation" if level_index == 0 and index > 0 else "initial", "--output", str(gate)]
                for side, child_index in (("left", 2 * index), ("right", 2 * index + 1)):
                    argv += ["--" + side, *child_args(previous_dirs[child_index], previous_nodes[child_index])]
                if args.backend == "metal":
                    argv += ["--metal-aot-bundle", str(args.aot_bundle.resolve()), "--metal-aot-manifest-sha256", args.aot_manifest_sha256]
                    if args.aot_profile is not None:
                        argv += ["--metal-aot-profile", args.aot_profile]
                run(name, argv)
                accepted = json.loads(gate.read_bytes())
                if not accepted["passed"] or not accepted["producer"]["exited_before_verification"]:
                    raise RuntimeError("parent did not independently verify after producer exit")
                parent_production_ns += accepted["producer"]["process_ns"]
                directories.append(directory)
                if root:
                    report["root"] = accepted["cases"][0]["receipt"]
            previous_dirs, previous_nodes = directories, level
        report.update(passed=True, leaf_production_ns=batch["process_ns"], parent_production_ns=parent_production_ns)
    finally:
        report["complete_gate_ns"] = time.monotonic_ns() - started
        report["maximum_rss_bytes"] = max((step.get("maximum_rss_bytes", 0) for step in report["steps"]), default=0)
        report["inputs_unchanged"] = all(path.is_file() and sha256(path) == pin for path, pin in inputs.items())
        if not report["inputs_unchanged"]:
            report["passed"] = False
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"]:
        raise RuntimeError(f"tree gate failed; retained report: {output / 'report.json'}")
    print(f"passed complete {count}-segment {args.backend} tree; report={output / 'report.json'}")


if __name__ == "__main__":
    main()
