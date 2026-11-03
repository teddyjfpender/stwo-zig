#!/usr/bin/env python3
"""Qualify compact OM31 DEEP kernels against native PCS fixtures on NVIDIA."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--fixtures", required=True, type=Path)
    p.add_argument("--build", required=True, type=Path)
    p.add_argument("--context-object", required=True, type=Path)
    p.add_argument("--lde-object", required=True, type=Path)
    p.add_argument("--n2b-object", required=True, type=Path)
    p.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    p.add_argument("--sanitizer", default="/usr/local/cuda/bin/compute-sanitizer")
    p.add_argument("--arch", choices=["89", "90", "100", "120"], default="120")
    args = p.parse_args()
    root, fixtures, build = args.source_root.resolve(), args.fixtures.resolve(), args.build.resolve()
    objects = [args.context_object.resolve(), args.lde_object.resolve(), args.n2b_object.resolve()]
    bins = [fixtures / f"case-{i}.bin" for i in range(4)]
    if not all(path.is_file() for path in objects + bins):
        p.error("the four native fixtures and all qualified dependency objects are required")
    build.mkdir(parents=True, exist_ok=True)
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", f"arch=compute_{args.arch},code=sm_{args.arch}",
             f"-I{root / 'src/backends/cuda/native'}", f"-I{root / 'tests/cuda/rv64'}", "-Xcompiler=-pthread"]
    source = root / "src/backends/cuda/native/rv64/deep.cu"
    driver = root / "tests/cuda/rv64/deep_smoke.cu"
    inputs = objects + bins + [source, driver, Path(__file__).resolve(),
        root / "src/backends/cuda/native/rv64/deep.h",
        root / "src/backends/cuda/native/rv64/om31.cuh",
        root / "src/backends/cuda/native/oods/field.cuh",
        root / "src/integrations/riscv_cuda/rv64_deep_fixture_main.zig"]
    pinned = {str(path): sha(path) for path in inputs}
    executable = build / "deep-smoke"
    started = time.monotonic()
    with (build / "compile.log").open("w") as log:
        subprocess.run([args.nvcc, *flags, "-Xptxas=-v", "-c", str(source), "-o", str(build / "deep.o")],
                       check=True, stdout=log, stderr=subprocess.STDOUT)
        subprocess.run([args.nvcc, *flags, str(driver), str(build / "deep.o"), *map(str, objects), "-o", str(executable)],
                       check=True, stdout=log, stderr=subprocess.STDOUT)
    compile_seconds = time.monotonic() - started
    gates = {}
    for tool in ["normal", "memcheck", "racecheck", "initcheck", "synccheck"]:
        command = [str(executable), str(fixtures)]
        if tool != "normal":
            command = [args.sanitizer, "--tool", tool, "--error-exitcode", "97", *command]
        path = build / f"{tool}.log"
        with path.open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        text = path.read_text()
        cases = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
        if (len(cases) != 23 or any(x["result"] != "PASS" for x in cases)
                or sum(x["fault"] == 0 and x["status"] == 0 for x in cases) != 4
                or sum(x["fault"] > 0 and x["status"] > 0 for x in cases) != 19):
            raise RuntimeError(f"incomplete DEEP qualification: {tool}")
        if tool != "normal" and not any(marker in text for marker in ["ERROR SUMMARY: 0 errors", "RACECHECK SUMMARY: 0 hazards displayed"]):
            raise RuntimeError(f"missing sanitizer success summary: {tool}")
        gates[tool] = {"status": "PASS", "sha256": sha(path)}
        print(json.dumps({"gate": tool, "status": "PASS"}), flush=True)
    receipt = {
        "schema": "rv64-cuda-om31-compact-deep/v1", "full_block_verified": False,
        "scope": "Native numerical quotient and compact aggregate/LDE parity; no proof or execution admission",
        "arch": args.arch, "compiler": subprocess.check_output([args.nvcc, "--version"], text=True),
        "compile_seconds": compile_seconds, "honest_cases": 4, "mutants_rejected": 19,
        "intermediate_field_transfers": 0, "source_sha256": sha(source), "driver_sha256": sha(driver),
        "fixture_generator_sha256": sha(root / "src/integrations/riscv_cuda/rv64_deep_fixture_main.zig"),
        "dependency_objects": {str(path): sha(path) for path in objects},
        "fixtures": {path.name: sha(path) for path in bins}, "gates": gates,
        "inputs_sha256": pinned, "executable_sha256": sha(executable), "object_sha256": sha(build / "deep.o"),
    }
    if any(sha(Path(path)) != digest for path, digest in pinned.items()):
        raise RuntimeError("qualification inputs changed during the run; refusing receipt")
    (build / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
