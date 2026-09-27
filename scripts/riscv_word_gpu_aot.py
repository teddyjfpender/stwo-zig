#!/usr/bin/env python3
"""Build typed word/range/two-event RAM AOT artifacts offline; never execute a GPU or proof.

An emitted source manifest records actual typed schemas. --compile-metal also
checks the complete generated library with Apple's offline compiler and pins
the resulting metallib. A receipt must be trusted independently of proof files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from zig_serial_build import build_lock

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_zig(zig: str, artifact: Path, root: str, kind: str = "build-exe") -> None:
    subprocess.run([
        zig, kind, "-OReleaseFast", "-lc", "-mcpu=native",
        "-femit-bin=" + str(artifact),
        "--dep", "stwo_core", "--dep", "stwo_prover_engine",
        "--dep", "stwo_cpu_backend", "--dep", "interop_postcard",
        "--dep", "stwo_prover_api", "--dep", "stwo_backend_contracts", "-Mroot=" + root,
        "-Mstwo_core=src/core/mod.zig", "--dep", "stwo_core",
        "--dep", "stwo_backend_contracts", "--dep", "stwo_prover_api",
        "-Mstwo_prover_engine=src/prover/mod.zig", "--dep", "stwo_core",
        "-Mstwo_backend_contracts=src/backend/mod.zig", "--dep", "stwo_core",
        "-Mstwo_prover_api=src/prover_api/mod.zig", "--dep", "stwo_core",
        "--dep", "stwo_prover_engine", "--dep", "stwo_backend_contracts",
        "-Mstwo_cpu_backend=src/backends/cpu_scalar/mod.zig", "--dep", "stwo_core",
        "--dep", "stwo_proof_wire", "-Minterop_postcard=src/interop/postcard.zig",
        "--dep", "stwo_core", "-Mstwo_proof_wire=src/interop/proof_wire/mod.zig",
    ], cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("metal", "cuda"), default="metal")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zig", default=shutil.which("zig") or "/opt/homebrew/opt/zig@0.15/bin/zig")
    parser.add_argument("--compile-metal", action="store_true", help="offline compilation, no GPU execution")
    parser.add_argument("--check-metal-runtime", action="store_true", help="compile actual quotient/resident-producer Zig bodies and syntax-check production Objective-C without running them")
    parser.add_argument("--check-cuda-runtime", action="store_true", help="compile real NativeSession Zig bridge to an object without linking or running CUDA")
    args = parser.parse_args()
    if args.compile_metal and args.target != "metal":
        parser.error("--compile-metal requires --target metal")
    if args.check_metal_runtime and args.target != "metal":
        parser.error("--check-metal-runtime requires --target metal")
    if args.check_cuda_runtime and args.target != "cuda":
        parser.error("--check-cuda-runtime requires --target cuda")
    destination = args.output.resolve()
    if destination.exists():
        parser.error("output already exists; choose a new directory to retain prior evidence")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Failed builds remain private; only a complete artifact is published.
    with tempfile.TemporaryDirectory(prefix=".word-aot-", dir=destination.parent) as temporary:
        work = Path(temporary)
        exporter = work / "exporter"
        with build_lock(label="word-gpu-aot"):
            build_zig(args.zig, exporter, "src/block_v5_word_gpu_aot_export.zig")
            if args.check_metal_runtime:
                build_zig(args.zig, work / "bridge.o", "src/block_v5_word_gpu_runtime_codegen.zig", "build-obj")
                build_zig(args.zig, work / "quotient_bridge.o", "src/block_v5_word_metal_quotient_codegen.zig", "build-obj")
                build_zig(args.zig, work / "resident_producer_bridge.o", "src/block_v5_ram_lanes_metal_producer_codegen.zig", "build-obj")
            if args.check_cuda_runtime:
                build_zig(args.zig, work / "bridge.o", "src/block_v5_word_cuda_runtime_codegen.zig", "build-obj")
        if args.check_metal_runtime:
            subprocess.run(["xcrun", "clang", "-fobjc-arc", "-fblocks", "-fsyntax-only", "src/backends/metal/runtime.m"], cwd=ROOT, check=True)
        artifact = work / "artifact"
        subprocess.run([str(exporter), args.target, str(artifact)], cwd=ROOT, check=True)
        manifest = json.loads((artifact / "source_manifest.json").read_text())
        source = artifact / manifest["source_file"]
        if sha256(source) != manifest["source_sha256"]:
            raise ValueError("exported source identity mismatch")
        receipt = {
            "version": 1, "target": args.target,
            "source_manifest_sha256": sha256(artifact / "source_manifest.json"),
            "exporter_sha256": sha256(exporter),
            "zig_version": subprocess.check_output([args.zig, "version"], text=True).strip(),
            "device_compiled": False, "device_executed": False,
            "stark_proved": False, "performance_measured": False,
            "zig_bridge_compiled": args.check_metal_runtime or args.check_cuda_runtime,
            "resident_quotient_bridge_compiled": args.check_metal_runtime,
            "resident_producer_bridge_compiled": args.check_metal_runtime,
            "objective_c_runtime_syntax_checked": args.check_metal_runtime,
            "build_sources": {
                path: sha256(ROOT / path) for path in (
                    "src/block_v5_word_gpu_aot_export.zig",
                    "src/block_v5_word_gpu_runtime_codegen.zig",
                    "scripts/riscv_word_gpu_aot.py",
                    "src/backends/metal/runtime/secure_polynomial_v1.zig",
                    "src/backends/metal/runtime/secure_polynomial_catalog_v1.m",
                    "src/backends/metal/runtime/secure_equations_v1.m",
                    "src/backends/metal/runtime/secure_interaction_v1.m",
                    "src/block_v5_word_metal_quotient_codegen.zig",
                    "src/backends/metal/runtime/secure_polynomial_composition_v1.zig",
                    "src/backends/metal/runtime/secure_coefficient_ingress_v1.zig",
                    "src/backends/metal/runtime/secure_coefficient_ingress_v1.m",
                    "src/backends/metal/shared_runtime.zig",
                    "src/backends/metal/commit_backend.zig",
                    "src/backends/metal/runtime.zig",
                    "src/backends/metal/runtime.m",
                    "src/backends/metal/runtime/resident_data.zig",
                    "src/backends/metal/runtime/resident_operations.zig",
                    "src/backends/metal/runtime/resident_budget_v1.zig",
                    "src/backends/metal/runtime/combined_commit_operations.zig",
                    "src/backends/metal/runtime/circle_transform_operations.zig",
                    "src/backends/metal/mod.zig",
                    "src/prover/host_budget_allocator.zig",
                    "src/prover/shared_external_memory_v1.zig",
                    "src/frontends/riscv/prover/block_v5_word_gpu_witness_v1.zig",
                    "src/block_v5_ram_lanes_metal_producer_codegen.zig",
                    "src/frontends/riscv/prover/block_v5_ram_lanes_proof_v1.zig",
                    "src/frontends/riscv/prover/block_v5_ram_lanes_stage_v1.zig",
                    "src/frontends/riscv/prover/block_v5_ram_lanes_replay_v1.zig",
                    "src/frontends/riscv/prover/block_v5_ram_lanes_resident_source_v1.zig",
                    "src/frontends/riscv/prover/block_v5_word_pcs_v1.zig",
                    "src/backends/metal/runtime/ram_lanes_producer_v1.zig",
                    "src/backends/metal/runtime/ram_lanes_witness_v1.metal",
                    "src/backends/metal/runtime/secure_resident_columns_v1.zig",
                    "src/backends/metal/runtime/secure_resident_columns_v1.m",
                    "src/prover/pcs/commitment_tree.zig",
                    "src/prover/pcs/commit_dispatch.zig",
                    "src/prover/pcs/backed_columns.zig",
                )
            },
        }
        if args.target == "cuda":
            receipt["build_sources"] = {
                path: sha256(ROOT / path) for path in (
                    "src/block_v5_word_gpu_aot_export.zig",
                    "src/block_v5_word_cuda_runtime_codegen.zig",
                    "scripts/riscv_word_gpu_aot.py",
                    "src/backends/cuda/runtime/secure_polynomial_v1.zig",
                    "src/backends/cuda/aot/secure_polynomial_registry_v1.zig",
                    "src/backends/cuda/secure_polynomial_codegen_v1.zig",
                    "src/backends/cuda/secure_polynomial_resident_codegen_v1.zig",
                    "src/backends/cuda/native/secure_polynomial_resident_v1.cuh",
                    "src/frontends/riscv/prover/block_v5_word_gpu_witness_v1.zig",
                )
            }
        # The six-program catalog binds the exact typed authorities; retain the
        # corresponding source files as independently inspectable build evidence.
        receipt["build_sources"].update({
            path: sha256(ROOT / path) for path in (
                "src/prover/air/secure_polynomial_program_v1.zig",
                "src/frontends/riscv/prover/block_v5_word_gpu_program_v1.zig",
                "src/frontends/riscv/prover/block_v5_ram_lanes_gpu_program_v1.zig",
                "src/frontends/riscv/prover/block_v5_ram_lanes_protocol_v1.zig",
                "src/frontends/riscv/prover/block_v5_ram_lanes_component_v1.zig",
                "src/frontends/riscv/prover/block_v5_ram_lanes_interaction_v1.zig",
                "src/frontends/riscv/air/block/word_memory_lanes_v1.zig",
                "src/frontends/riscv/air/block/word_memory_lanes_trace_v1.zig",
            )
        })
        if args.check_metal_runtime or args.check_cuda_runtime:
            receipt["bridge_object_sha256"] = sha256(work / "bridge.o")
        if args.check_metal_runtime:
            receipt["quotient_bridge_object_sha256"] = sha256(work / "quotient_bridge.o")
            receipt["resident_producer_bridge_object_sha256"] = sha256(work / "resident_producer_bridge.o")
        if args.compile_metal:
            metal_path = subprocess.check_output(["xcrun", "--find", "metal"], text=True).strip()
            receipt["metal_compiler"] = metal_path
            receipt["metal_version"] = subprocess.check_output([metal_path, "--version"], text=True).strip()
            air = work / "kernels.air"
            subprocess.run([metal_path, "-std=metal3.1", "-c", str(source), "-o", str(air)], check=True)
            subprocess.run(["xcrun", "metallib", str(air), "-o", str(artifact / "kernels.metallib")], check=True)
            receipt.update(device_compiled=True, binary_file="kernels.metallib", binary_sha256=sha256(artifact / "kernels.metallib"))
        (artifact / "artifact_manifest.json").write_text(json.dumps(receipt, indent=2) + "\n")
        os.rename(artifact, destination)
    print(json.dumps({"output": str(destination), **receipt}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
