#!/usr/bin/env bash
# Run the CUDA bit-identity suite on the device (the same assertions as
# `zig build test-cuda-emu`), the emulation suite, and the plain CPU suite.
#   scripts/tensor_cuda_test.sh [sm_90|sm_120]
# Optional: TENSOR_CUDA_SANITIZE=1 runs the device suite under compute-sanitizer.
set -euo pipefail
ARCH="${1:-${CUDA_ARCH:-sm_90}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/src/tensor"
NVCC="${NVCC:-$(command -v nvcc || echo /usr/local/cuda/bin/nvcc)}"
COMMON=(-Doptimize=ReleaseSafe -Dcuda=true -Dcuda-arch="$ARCH" -Dnvcc="$NVCC" -Dmetal=false --summary all)
echo "== emulation suite (CPU)"; zig build test-cuda-emu "${COMMON[@]}"
echo "== device suite"; zig build test-cuda "${COMMON[@]}"
if [[ "${TENSOR_CUDA_SANITIZE:-0}" == 1 ]]; then
  # install the device test binary at a fixed path, then run it under the sanitizer
  # (a find over .zig-cache could pick the emulation or CPU test binary, which
  # make no CUDA calls and would pass vacuously)
  zig build install-cuda-test "${COMMON[@]}"
  BIN="$PWD/zig-out/bin/tensor-cuda-test"
  for tool in memcheck racecheck synccheck; do
    echo "== compute-sanitizer --tool $tool"; compute-sanitizer --tool "$tool" --error-exitcode 1 "$BIN"
  done
fi
echo "== CPU suite"; zig build test -Doptimize=ReleaseSafe -Dmetal=false --summary all
