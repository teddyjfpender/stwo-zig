#!/usr/bin/env python3
"""Reject a GPU host that reports a device but cannot run CUDA work.

Run this before downloading fixtures or building the prover. In particular,
``nvidia-smi`` can succeed on a pod whose CUDA context cannot be created.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


SOURCE = r"""
#include <cuda_runtime.h>
#include <cstdio>

__global__ void increment(unsigned int* value) { value[0] += 1; }

int main() {
    auto step = [](const char* label, cudaError_t status) {
        if (status != cudaSuccess) {
            std::fprintf(stderr, "%s: %d %s\n", label, int(status),
                         cudaGetErrorString(status));
            return false;
        }
        return true;
    };
    if (!step("cudaSetDevice", cudaSetDevice(0))) return 1;
    unsigned int* value = nullptr;
    if (!step("cudaMallocManaged", cudaMallocManaged(&value, sizeof(*value))))
        return 1;
#if CUDART_VERSION >= 13000
    const cudaMemLocation host{cudaMemLocationTypeHost, 0};
    const cudaMemLocation device{cudaMemLocationTypeDevice, 0};
    if (!step("cudaMemAdvise host", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseSetPreferredLocation, host))) return 1;
    if (!step("cudaMemAdvise device access", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseSetAccessedBy, device))) return 1;
    if (!step("cudaMemPrefetchAsync", cudaMemPrefetchAsync(value, sizeof(*value),
               device, 0, nullptr))) return 1;
#else
    if (!step("cudaMemAdvise host", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseSetPreferredLocation, cudaCpuDeviceId))) return 1;
    if (!step("cudaMemAdvise device access", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseSetAccessedBy, 0))) return 1;
    if (!step("cudaMemPrefetchAsync", cudaMemPrefetchAsync(value, sizeof(*value),
               0, nullptr))) return 1;
#endif
    *value = 41;
    increment<<<1, 1>>>(value);
    if (!step("kernel launch", cudaGetLastError())) return 1;
    if (!step("cudaDeviceSynchronize", cudaDeviceSynchronize())) return 1;
    if (*value != 42) {
        std::fprintf(stderr, "managed-memory kernel returned %u, expected 42\n",
                     *value);
        return 1;
    }
#if CUDART_VERSION >= 13000
    if (!step("cudaMemAdvise unset access", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseUnsetAccessedBy, device))) return 1;
    if (!step("cudaMemAdvise unset preference", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseUnsetPreferredLocation, host))) return 1;
#else
    if (!step("cudaMemAdvise unset access", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseUnsetAccessedBy, 0))) return 1;
    if (!step("cudaMemAdvise unset preference", cudaMemAdvise(value, sizeof(*value),
               cudaMemAdviseUnsetPreferredLocation, cudaCpuDeviceId))) return 1;
#endif
    if (!step("cudaFree", cudaFree(value))) return 1;
    std::puts("CUDA context, managed advice, prefetch, kernel, and synchronization passed");
    return 0;
}
"""


def capture(command: list[str]) -> dict[str, object]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nvcc", type=Path, default=Path(shutil.which("nvcc") or "nvcc"))
    parser.add_argument("--arch", default="sm_120")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()

    device = capture([
        "nvidia-smi", "--query-gpu=name,uuid,compute_cap,driver_version,memory.total",
        "--format=csv,noheader",
    ])
    with tempfile.TemporaryDirectory(prefix="cuda-host-preflight-") as directory:
        source = Path(directory) / "preflight.cu"
        executable = Path(directory) / "preflight"
        source.write_text(SOURCE, encoding="utf-8")
        build = capture([str(args.nvcc), f"-arch={args.arch}", str(source), "-o", str(executable)])
        run = capture([str(executable)]) if build["returncode"] == 0 else None

    receipt = {
        "schema": "stwo-zig-cuda-host-preflight-v1",
        "hostname": os.uname().nodename,
        "device": device,
        "build": build,
        "run": run,
        "passed": device["returncode"] == 0
        and build["returncode"] == 0
        and run is not None
        and run["returncode"] == 0,
    }
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
