#!/usr/bin/env python3
"""Build and freshly verify the pinned four-segment experimental CPU/Metal tree.

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
ADMISSION = ROOT / "vectors/reports/recursive-product-20260917/canonical-admission-v2/admission.json"
ADMISSION_SHA256 = "1fe20e6c7ee8daec966ccf2aa601e9e417d1aa37e9e96e8d9290c8ae18d90a89"
OTHER_ADMISSION = ROOT / "vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/tree-admissions/air-fusion-q193-4-seed14.json"
OTHER_ADMISSION_SHA256 = "c7b278867cee07a660be4e2ec16f71db78f1bb7dd51ed74cf26e2c683dea4b07"


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
    parser.add_argument("--admission", type=Path, help="independently reviewed four-segment tree admission")
    parser.add_argument("--admission-sha256", help="required exact digest when overriding admission")
    args = parser.parse_args()
    if (args.admission is None) != (args.admission_sha256 is None):
        parser.error("--admission and --admission-sha256 must be supplied together")
    admission = args.admission.resolve() if args.admission is not None else ADMISSION
    admission_sha256 = args.admission_sha256 or ADMISSION_SHA256
    if len(admission_sha256) != 64 or any(c not in "0123456789abcdef" for c in admission_sha256):
        parser.error("admission digest must be lowercase SHA-256 hex")
    zig_version = subprocess.check_output(["zig", "version"], text=True).strip()
    if zig_version != "0.15.2":
        parser.error(f"this admitted build requires Zig 0.15.2, found {zig_version}")
    if args.backend == "metal" and sys.platform != "darwin":
        parser.error("Metal requires a physical Mac and the full Xcode Metal toolchain")
    if sha256(admission) != admission_sha256:
        parser.error("reviewed tree admission digest mismatch")
    if sha256(OTHER_ADMISSION) != OTHER_ADMISSION_SHA256:
        parser.error("reviewed substitution admission digest mismatch")
    output = args.output.resolve()
    if output.is_relative_to(ROOT) and not output.is_relative_to(ROOT / "zig-out"):
        parser.error("repository outputs must be under zig-out; an external directory is also supported")
    output.mkdir(parents=True, exist_ok=False)
    snapshot = source_snapshot()
    report = {
        "schema": "stwo.recursive-product.v1", "backend": args.backend,
        "profile": "recursive_q193_v1", "production_security_qualified": False,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "zig_version": zig_version,
        "source_sha256": snapshot, "admission_sha256": admission_sha256,
        "substitution_admission_sha256": OTHER_ADMISSION_SHA256,
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
                   "--admission-sha256", admission_sha256, "--output", str(output / "tree")]
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
            if len(native_device) != 4 or any(row.get("table_interaction_dispatches") != "24" for row in native_device):
                raise RuntimeError("all six native tables must execute device interactions for every child")
            report["native_table_interactions"] = {"tables_per_child": 6, "children": 4, "successful_device_dispatches": 96}
            leaf_device = records((output / "tree/produce-leaves.log").read_text(), "DETACHED_LEAF_TYPED_DEVICE_INTERACTION")
            if len(leaf_device) != 4 or any(row.get("components") != "36" or row.get("inactive_zero_components") != "1" or row.get("dispatches") != "144" for row in leaf_device):
                raise RuntimeError("all 36 active typed components must execute device interactions for every leaf")
            report["leaf_typed_interactions"] = {"components_per_leaf": 36, "inactive_zero_components_per_leaf": 1, "leaves": 4, "successful_device_dispatches": 576}
            parent_device = []
            for log in sorted((output / "tree").glob("parent-*-accepted.json.producer.log")):
                parent_device.extend(records(log.read_text(), "DETACHED_PARENT_TYPED_DEVICE_INTERACTION"))
            if len(parent_device) != 3 or any(row.get("components") != "29" or row.get("dispatches") != "116" for row in parent_device):
                raise RuntimeError("all 29 typed components must execute device interactions for every parent")
            report["parent_typed_interactions"] = {"components_per_parent": 29, "parents": 3, "successful_device_dispatches": 348}
        original = json.loads(admission.read_bytes())
        other = json.loads(OTHER_ADMISSION.read_bytes())
        for index, (node, substitute) in enumerate(zip(original["leaves"], other["leaves"], strict=True)):
            expected = admission.parent / node["expected"]["path"]
            wrong = OTHER_ADMISSION.parent / substitute["expected"]["path"]
            if (node["key"]["sha256"] != substitute["key"]["sha256"] or sha256(expected) != node["expected"]["sha256"]
                    or sha256(wrong) != substitute["expected"]["sha256"]
                    or len(json.loads(expected.read_bytes())) != len(json.loads(wrong.read_bytes()))
                    or expected.read_bytes() == wrong.read_bytes()):
                raise RuntimeError("substitution must have the same key and geometry and a distinct pinned statement")
            run(f"substitution-{index}", [sys.executable,
                str(ROOT / "scripts/riscv_segment_v2_detached_gate.py"),
                "--proof-profile", "recursive_q193_v1", "--verifier", str(binaries["leaf-verifier"]),
                "--bundle", str(output / f"tree/leaves/child-{index}"),
                "--key-sha256", node["key"]["sha256"], "--expected-wire", str(expected),
                "--other-expected-wire", str(wrong),
                "--output", str(output / f"substitution-{index}.json")], timeout=120)
            if sha256(wrong) != substitute["expected"]["sha256"]:
                raise RuntimeError("substitution input changed during verification")
        if (source_snapshot() != snapshot or sha256(admission) != admission_sha256
                or sha256(OTHER_ADMISSION) != OTHER_ADMISSION_SHA256
                or any(sha256(path) != report["binary_sha256"][role] for role, path in binaries.items())):
            raise RuntimeError("source, admission or executable changed during verification")
        report["tree_report_sha256"] = sha256(output / "tree/report.json")
        report["passed"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
