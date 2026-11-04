#!/usr/bin/env bash
# Build the tensor prover with the CUDA backend on an NVIDIA host.
#   scripts/tensor_cuda_build.sh [sm_90|sm_120|...]   (H100 = sm_90, RTX 5090 = sm_120)
# Needs: zig 0.15.2, CUDA toolkit >= 12.8 (nvcc on PATH or NVCC=...), a driver.
set -euo pipefail
ARCH="${1:-${CUDA_ARCH:-sm_90}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/src/tensor"
NVCC="${NVCC:-$(command -v nvcc || echo /usr/local/cuda/bin/nvcc)}"
echo "nvcc: $NVCC ($("$NVCC" --version | tail -1))"
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader || true
zig build -Doptimize=ReleaseFast -Dcuda=true -Dcuda-arch="$ARCH" -Dnvcc="$NVCC" -Dmetal=false
ls -la zig-out/bin/tensor-bench zig-out/lib/libtensor_cuda.so
