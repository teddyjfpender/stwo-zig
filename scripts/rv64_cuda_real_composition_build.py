#!/usr/bin/env python3
"""Link the real hybrid composition helper from pinned cached joined kernels."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source-root", "kernel-build", "objects", "build"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--grouped-kernel-build", type=Path)
    args = parser.parse_args()
    root, old, objects, build = (getattr(args, key).resolve() for key in ["source_root", "kernel_build", "objects", "build"])
    build.mkdir(parents=True, exist_ok=True)
    unavailable = [] if args.grouped_kernel_build else [41, 43, 44]
    ids = [i for i in range(49) if i not in unavailable]
    kernels = [(args.grouped_kernel_build.resolve() if i == 41 and args.grouped_kernel_build else old) / f"case-{i}-domain.o" for i in ids]
    for path in kernels:
        if not path.is_file():
            parser.error("missing cached native joined kernel: " + str(path))
        manifest = json.loads(path.with_suffix(".sha256").read_text())
        if manifest["object_sha256"] != sha(path):
            parser.error("cached kernel object changed: " + str(path))
        for dep, digest in manifest["dependencies"].items():
            if sha(Path(dep)) != digest:
                parser.error("cached kernel dependency changed: " + dep)
    libraries = [objects / name for name in ["context.o", "transform-lde.o", "transform-n2b.o"]]
    driver = root / "tests/cuda/rv64/real_composition_driver.cu"
    header = '#pragma once\n#include <cuda_runtime.h>\n#include <cstdint>\n'
    for i in ids:
        header += f'extern "C" __global__ void rv64_joined_domain_{i}(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);\n'
    header += 'static const void *real_kernels[]={' + ','.join(f'(void*)rv64_joined_domain_{i}' if i in ids else 'nullptr' for i in range(49)) + '};\n'
    header += 'static const uint32_t real_root_group_sizes[]={' + ','.join('32' if i == 41 and args.grouped_kernel_build else '0' for i in range(49)) + '};\n'
    (build / "real_composition_launches.h").write_text(header)
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-pthread", f"-I{root}/src/backends/cuda/native", f"-I{root}/tests/cuda/rv64", f"-I{build}"]
    executable = build / "real-composition"
    started = time.monotonic()
    with (build / "compile.log").open("w") as log:
        subprocess.run(["/usr/local/cuda/bin/nvcc", *flags, str(driver), *map(str, kernels + libraries), "-o", str(executable)], check=True, stdout=log, stderr=subprocess.STDOUT)
    inputs = [driver, root / "tests/cuda/rv64/context_owner.cuh", root / "tests/cuda/rv64/fixture_words.cuh", *kernels, *libraries, Path(__file__).resolve()]
    receipt = {"schema": "rv64-hybrid-real-composition-build/v1", "gpu_layouts": ids, "cpu_layouts": unavailable,
               "scope": "Native prover composition offload; CPU witness/auxiliary generation and bucket lifting retained",
               "link_seconds": time.monotonic() - started, "input_sha256": {str(path): sha(path) for path in inputs}, "executable_sha256": sha(executable), "real_segment_verified": False}
    (build / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(executable)


if __name__ == "__main__":
    main()
