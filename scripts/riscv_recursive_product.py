#!/usr/bin/env python3
"""Build and freshly verify an independently pinned SegmentV2 CPU/Metal tree.

All executables and (for Metal) the AOT bundle are built into a new output
directory. No retained session binary is an input. The existing tree gate owns
producer destruction, independent statement/key admission and hostile replay.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_snapshot() -> dict[str, str]:
    paths = subprocess.check_output([
        "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
        "--", "build.zig", "build.zig.zon", "build_support", "src", "scripts",
        "design", "conformance",
    ], cwd=ROOT).decode().split("\0")
    return {path: sha256(ROOT / path) for path in sorted(set(paths))
            if path and (ROOT / path).is_file()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("cpu", "metal"), required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence/build directory")
    parser.add_argument("--admission", type=Path, required=True,
                        help="freshly regenerated, independently reviewed tree admission")
    parser.add_argument("--admission-sha256", required=True)
    parser.add_argument("--other-inputs", type=Path, required=True,
                        help="same-geometry workload with a distinct memory seed")
    parser.add_argument("--other-inputs-sha256", required=True)
    args = parser.parse_args()
    admission = args.admission.resolve()
    other_inputs = args.other_inputs.resolve()
    for name, digest in (("admission", args.admission_sha256),
                         ("other inputs", args.other_inputs_sha256)):
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            parser.error(f"{name} digest must be lowercase SHA-256 hex")
    zig_version = subprocess.check_output(["zig", "version"], text=True).strip()
    if zig_version != "0.15.2":
        parser.error(f"this admitted build requires Zig 0.15.2, found {zig_version}")
    if args.backend == "metal" and sys.platform != "darwin":
        parser.error("Metal requires a physical Mac and the full Xcode Metal toolchain")
    if sha256(admission) != args.admission_sha256:
        parser.error("reviewed tree admission digest mismatch")
    if sha256(other_inputs) != args.other_inputs_sha256:
        parser.error("reviewed substitution workload digest mismatch")
    tree = json.loads(admission.read_bytes())
    alternate = json.loads(other_inputs.read_bytes())
    segment_count = len(tree["leaves"])
    if (segment_count not in (1, 2, 4, 8) or
            len(alternate["leaf_expected"]) != segment_count or
            tree["profile"] != alternate["profile"] or
            tree["memory_addresses"] != alternate["memory_addresses"] or
            tree["initial_memory_word"] == alternate["initial_memory_word"]):
        parser.error("substitution workload must have matching geometry and a distinct seed")
    output = args.output.resolve()
    if output.is_relative_to(ROOT) and not output.is_relative_to(ROOT / "zig-out"):
        parser.error("repository outputs must be under zig-out; an external directory is also supported")
    output.mkdir(parents=True, exist_ok=False)
    snapshot = source_snapshot()
    report = {
        "schema": "stwo.recursive-product.v1", "backend": args.backend,
        "profile": "recursive_q193_v1", "production_security_qualified": False,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "segments": segment_count,
        "zig_version": zig_version,
        "source_sha256": snapshot, "admission_sha256": args.admission_sha256,
        "substitution_inputs_sha256": args.other_inputs_sha256,
        "steps": [], "passed": False,
    }
    environment = dict(os.environ)
    # The baseline is explicitly hybrid. Strict coverage has its own admission
    # gates and cannot be inferred from a successful hybrid complete proof.
    environment["STWO_ZIG_METAL_REQUIRE_GPU"] = "0"
    report["stwo_environment"] = {k: v for k, v in environment.items() if k.startswith("STWO_")}

    def save() -> None:
        (output / "product.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(name: str, command: list[str], timeout: int = 3600) -> None:
        entry = {"name": name, "argv": command}
        report["steps"].append(entry)
        save()
        print(f"{name}: started", flush=True)
        started = time.monotonic_ns()
        log = output / (name + ".log")
        try:
            with log.open("xb") as stream:
                process = subprocess.Popen(command, cwd=ROOT, env=environment,
                                           stdout=stream, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    status = process.wait(timeout=timeout)
                except BaseException:
                    # Cancel the stage's producer/compiler descendants as well.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise
            entry["exit_code"] = status
            if status:
                raise RuntimeError(f"{name} failed; inspect {log}")
        finally:
            entry["elapsed_ns"] = time.monotonic_ns() - started
            if log.exists():
                entry["log_sha256"] = sha256(log)
            save()
        print(f"{name}: passed in {entry['elapsed_ns'] / 1e9:.3f}s", flush=True)

    def build(name: str, cwd: str, prefix: Path, targets: list[str]) -> None:
        run(name, [sys.executable, str(ROOT / "scripts/zig_serial_build.py"),
                   "--cwd", str(ROOT / cwd), *targets, "-Doptimize=ReleaseSafe",
                   "--prefix", str(prefix), "--summary", "all"])

    try:
        cpu = output / "cpu"
        cpu_targets = ["build-recursive-segment-v2-detached-verifier",
                       "build-recursive-segment-v2-detached-parent-verifier"]
        if args.backend == "cpu":
            cpu_targets += ["build-recursive-segment-v2-detached-leaf-producer",
                            "build-recursive-segment-v2-detached-parent-producer"]
        build("build-cpu", "src/integrations/riscv_cpu", cpu, cpu_targets)
        producer_prefix = cpu
        aot_args: list[str] = []
        if args.backend == "metal":
            producer_prefix = output / "metal"
            build("build-metal", "src/integrations/riscv_metal", producer_prefix,
                  ["build-recursive-segment-v2-detached-leaf-producer",
                   "build-recursive-segment-v2-detached-parent-producer"])
            tool = output / "aot-tool"
            build("build-aot-tool", ".", tool, ["metal-core-aot"])
            bundle = output / "aot"
            run("build-aot", [str(tool / "bin/metal-core-aot"), "build", "--output-dir",
                              str(bundle), "--profile", "recursive-framework-v1"])
            aot_args = ["--aot-bundle", str(bundle), "--aot-manifest-sha256",
                        sha256(bundle / "stwo_zig_core.manifest.json"),
                        "--aot-profile", "recursive-framework-v1"]
        if source_snapshot() != snapshot:
            raise RuntimeError("source changed during build; retain evidence and restart from frozen source")
        binaries = {
            "leaf-producer": producer_prefix / ("bin/recursive-segment-v2-detached-leaf-prove"
                                                + ("-metal" if args.backend == "metal" else "")),
            "parent-producer": producer_prefix / ("bin/recursive-segment-v2-detached-parent-prove"
                                                  + ("-metal" if args.backend == "metal" else "")),
            "leaf-verifier": cpu / "bin/recursive-segment-v2-detached-verify",
            "parent-verifier": cpu / "bin/recursive-segment-v2-detached-parent-verify",
        }
        command = [sys.executable, str(ROOT / "scripts/riscv_segment_v2_detached_tree_gate.py"),
                   "--backend", args.backend, "--admission", str(admission),
                   "--admission-sha256", args.admission_sha256, "--output", str(output / "tree")]
        report["binary_sha256"] = {role: sha256(path) for role, path in binaries.items()}
        for role, path in binaries.items():
            command += ["--" + role, str(path), "--" + role + "-sha256", report["binary_sha256"][role]]
        run("complete-tree", command + aot_args, timeout=1800)
        tree = json.loads((output / "tree/report.json").read_text())
        if tree.get("passed") is not True or source_snapshot() != snapshot:
            raise RuntimeError("complete-tree acceptance or frozen-source check failed")
        if args.backend == "metal":
            from riscv_segment_v2_detached_gate import records
            native_device = records((output / "tree/produce-leaves.log").read_text(), "SEGMENT_V2_TWO_CHILD_NATIVE_METAL")
            if len(native_device) != segment_count or any(row.get("table_interaction_dispatches") != "24" for row in native_device):
                raise RuntimeError("all six native tables must execute device interactions for every child")
            report["native_table_interactions"] = {"tables_per_child": 6, "children": segment_count,
                                                    "successful_device_dispatches": 24 * segment_count}
            leaf_device = records((output / "tree/produce-leaves.log").read_text(), "DETACHED_LEAF_TYPED_DEVICE_INTERACTION")
            if len(leaf_device) != segment_count or any(row.get("components") != "36" or row.get("inactive_zero_components") != "1" or row.get("dispatches") != "144" for row in leaf_device):
                raise RuntimeError("all 36 active typed components must execute device interactions for every leaf")
            report["leaf_typed_interactions"] = {"components_per_leaf": 36, "inactive_zero_components_per_leaf": 1,
                                                 "leaves": segment_count, "successful_device_dispatches": 144 * segment_count}
            parent_device = []
            for log in sorted((output / "tree").glob("parent-*-accepted.json.producer.log")):
                parent_device.extend(records(log.read_text(), "DETACHED_PARENT_TYPED_DEVICE_INTERACTION"))
            if len(parent_device) != segment_count - 1 or any(row.get("components") != "29" or row.get("dispatches") != "116" for row in parent_device):
                raise RuntimeError("all 29 typed components must execute device interactions for every parent")
            report["parent_typed_interactions"] = {"components_per_parent": 29, "parents": segment_count - 1,
                                                   "successful_device_dispatches": 116 * (segment_count - 1)}
        substitution = output / "statement-substitution.json"
        run("statement-substitution", [sys.executable,
            str(ROOT / "scripts/riscv_segment_v2_statement_substitution.py"),
            "--admission", str(admission), "--admission-sha256", args.admission_sha256,
            "--other-inputs", str(other_inputs), "--other-inputs-sha256", args.other_inputs_sha256,
            "--leaf-verifier", str(binaries["leaf-verifier"]),
            "--leaf-verifier-sha256", report["binary_sha256"]["leaf-verifier"],
            "--parent-verifier", str(binaries["parent-verifier"]),
            "--parent-verifier-sha256", report["binary_sha256"]["parent-verifier"],
            "--tree", str(output / "tree"), "--output", str(substitution)], timeout=300)
        if json.loads(substitution.read_bytes()).get("passed") is not True:
            raise RuntimeError("statement substitution gate did not pass")
        if (source_snapshot() != snapshot or sha256(admission) != args.admission_sha256
                or sha256(other_inputs) != args.other_inputs_sha256
                or any(sha256(path) != report["binary_sha256"][role] for role, path in binaries.items())):
            raise RuntimeError("source, admission or executable changed during verification")
        report["tree_report_sha256"] = sha256(output / "tree/report.json")
        report["substitution_report_sha256"] = sha256(substitution)
        report["passed"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
