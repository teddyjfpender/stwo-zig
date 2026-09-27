#!/usr/bin/env python3
"""Export actual native AIR capabilities and optionally compile/install them offline.

This path never executes a guest, proof or GPU. --update-source updates the
checked-in shader, native manifest entries and matching runtime bootstrap as
one inventory; unrelated kernel families are preserved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from riscv_word_gpu_aot import ROOT, build_zig
from zig_serial_build import build_lock


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def update_source(source: str, names: list[str]) -> None:
    if len(names) != len(set(names)):
        raise ValueError("duplicate native kernel identity")
    manifest_path = ROOT / "src/backends/metal/shaders/manifest.zig"
    runtime_path = ROOT / "src/backends/metal/runtime.m"
    manifest = manifest_path.read_text()
    pattern = re.compile(r'^    \.\{ \.name = "stwo_zig_(?:base_poly_|lookup_poly_)[^"]+", \.owner = \.riscv_polynomials \},\n', re.M)
    matches = list(pattern.finditer(manifest))
    if not matches or any(left.end() != right.start() for left, right in zip(matches, matches[1:])):
        raise ValueError("native manifest inventory must be one contiguous region")
    old_names = [re.search(r'\.name = "([^"]+)"', match.group()).group(1) for match in matches]
    if not set(old_names).issubset(names):
        raise ValueError("new native inventory dropped an existing admitted recipe")
    generated_manifest = "".join(f'    .{{ .name = "{name}", .owner = .riscv_polynomials }},\n' for name in names)
    manifest = manifest[:matches[0].start()] + generated_manifest + manifest[matches[-1].end():]
    runtime = runtime_path.read_text()
    start_marker = "        // BEGIN GENERATED RISC-V POLYNOMIAL PIPELINES."
    end_marker = "        // END GENERATED RISC-V POLYNOMIAL PIPELINES."
    if runtime.count(start_marker) != 1 or runtime.count(end_marker) != 1:
        raise ValueError("ambiguous native runtime inventory")
    start = runtime.index(start_marker)
    end = runtime.index(end_marker, start) + len(end_marker)
    lines = [start_marker, "        // Generated from actual native AIR capabilities; keep manifest order."]
    for index, name in enumerate(names):
        variable = f"riscvPolynomialName{index:02d}"
        lines += [
            f'        NSString *{variable} = @"{name}";',
            f"        runtime.riscvPolynomialPipelines[{variable}] = make_pipeline(",
            f"            device, library, {variable}, error_message, error_message_len);",
            f"        if (runtime.riscvPolynomialPipelines[{variable}] == nil) return NULL;",
        ]
    lines.append(end_marker)
    runtime = runtime[:start] + "\n".join(lines) + runtime[end:]
    runtime, capacity_count = re.subn(
        r'runtime\.riscvPolynomialPipelines = \[NSMutableDictionary dictionaryWithCapacity:\d+u\];',
        f"runtime.riscvPolynomialPipelines = [NSMutableDictionary dictionaryWithCapacity:{len(names)}u];",
        runtime,
    )
    if capacity_count != 1:
        raise ValueError("ambiguous native pipeline dictionary")
    # Derive all files before mutating the worktree.
    (ROOT / "src/backends/metal/shaders/core/riscv_polynomials.metal").write_text(source)
    manifest_path.write_text(manifest)
    runtime_path.write_text(runtime)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zig", default="/opt/homebrew/opt/zig@0.15/bin/zig")
    parser.add_argument("--compile-metal", action="store_true")
    parser.add_argument("--update-source", action="store_true")
    args = parser.parse_args()
    destination = args.output.resolve()
    if destination.exists():
        parser.error("output already exists; use a new directory to preserve evidence")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".native-aot-", dir=destination.parent) as temporary:
        work = Path(temporary)
        exporter = work / "exporter"
        with build_lock(label="native-polynomial-aot"):
            build_zig(args.zig, exporter, "src/riscv_native_polynomial_aot_export.zig")
        artifact = work / "artifact"
        subprocess.run([str(exporter), str(artifact)], cwd=ROOT, check=True)
        catalog = json.loads((artifact / "source_manifest.json").read_text())
        source_path = artifact / catalog["source_file"]
        if digest(source_path) != catalog["source_sha256"]:
            raise ValueError("native source identity mismatch")
        names = list(dict.fromkeys(entry["kernel"] for entry in catalog["programs"]))
        source = source_path.read_text()
        if any(len(re.findall(r'kernel void ' + re.escape(name) + r'\(', source)) != 1 for name in names):
            from collections import Counter
            duplicates = {name: count for name, count in Counter(names).items() if count != 1}
            declarations = {name: len(re.findall(r'kernel void ' + re.escape(name) + r'\(', source)) for name in names}
            raise ValueError(f"native source inventory mismatch: duplicate identities={duplicates}, wrong declarations={ {name: count for name, count in declarations.items() if count != 1} }")
        receipt = {
            "version": 1,
            "source_manifest_sha256": digest(artifact / "source_manifest.json"),
            "exporter_sha256": digest(exporter),
            "zig_version": subprocess.check_output([args.zig, "version"], text=True).strip(),
            "program_count": len(catalog["programs"]),
            "kernel_count": len(names),
            "local_zero_base_count": sum(entry["kind"] == "base" and entry["program_id"] >> 32 == 7 for entry in catalog["programs"]),
            "local_zero_lookup_count": sum(entry["kind"] == "lookup" and entry["program_id"] >> 32 == 8 for entry in catalog["programs"]),
            "device_compiled": False,
            "device_executed": False,
            "guest_executed": False,
            "stark_proved": False,
            "performance_measured": False,
            "canonical_x0_activation": False,
        }
        if args.compile_metal:
            compiler = subprocess.check_output(["xcrun", "--find", "metal"], text=True).strip()
            intermediate = work / "kernels.air"
            flags = ["-std=metal3.1", "-fno-fast-math", "-Werror"]
            subprocess.run([compiler, *flags, "-c", str(source_path), "-o", str(intermediate)], check=True)
            subprocess.run(["xcrun", "metallib", str(intermediate), "-o", str(artifact / "kernels.metallib")], check=True)
            receipt.update(device_compiled=True, binary_sha256=digest(artifact / "kernels.metallib"), metal_compiler=compiler, metal_version=subprocess.check_output([compiler, "--version"], text=True).strip(), compile_flags=flags)
        if args.update_source:
            update_source(source, names)
            subprocess.run(["xcrun", "clang", "-fobjc-arc", "-fblocks", "-fsyntax-only", "src/backends/metal/runtime.m"], cwd=ROOT, check=True)
        receipt["checked_in_sources_updated"] = args.update_source
        receipt["build_sources"] = {path: digest(ROOT / path) for path in (
            "scripts/riscv_native_polynomial_aot.py",
            "src/riscv_native_polynomial_aot_export.zig",
            "src/frontends/riscv/air/native_polynomial_inventory_v1.zig",
            "src/frontends/riscv/air/semantic_component.zig",
            "src/frontends/riscv/air/lookups/opcode_component.zig",
            "src/frontends/riscv/air/x0_native_envelope_v1.zig",
            "src/frontends/riscv/air/x0_local_custody_v1.zig",
            "src/frontends/riscv/air/semantic_eval.zig",
            "src/frontends/riscv/air/constraint_program.zig",
            "src/frontends/riscv/air/lang/row_window.zig",
            "src/frontends/riscv/air/lookups/entry.zig",
            "src/frontends/riscv/air/lookups/opcode_entries.zig",
            "src/frontends/riscv/air/extract/runtime_program.zig",
            "src/frontends/riscv/air/extract/model.zig",
            "src/frontends/riscv/air/extract/symbolic.zig",
            "src/frontends/riscv/air/memory_commitment/hash_runtime_program.zig",
            "src/frontends/riscv/air/lang/lookup_batch_execution.zig",
            "src/frontends/riscv/air/lang/lookup_polynomial_program_v2.zig",
            "src/frontends/riscv/air/lang/typed_poseidon2_degree_bounded_candidate.zig",
            "src/frontends/riscv/air/lang/typed_poseidon2_degree5_backend.zig",
            "src/prover/air/component_programs.zig",
            "src/backends/metal/runtime/riscv_polynomial_aot_codegen.zig",
            "src/backends/metal/runtime/base_polynomial_codegen.zig",
            "src/backends/metal/runtime/lookup_polynomial_codegen.zig",
            "src/backends/metal/runtime/lookup_polynomial_v2_codegen.zig",
            "src/backends/metal/shaders/core/riscv_polynomials.metal",
            "src/backends/metal/shaders/manifest.zig",
            "src/backends/metal/runtime.m",
        )}
        (artifact / "artifact_manifest.json").write_text(json.dumps(receipt, indent=2) + "\n")
        os.rename(artifact, destination)
    print(json.dumps({"output": str(destination), **{key: value for key, value in receipt.items() if key != "build_sources"}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
