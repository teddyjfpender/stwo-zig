#!/usr/bin/env bash
# No-GPU check of the real CUDA path: lowers every kernel of tc_host.cu
# (__CUDACC__ defined) to PTX with LLVM's NVPTX backend for sm_90 and sm_120,
# and parses the host side, against a minimal runtime stub
# (src/tensor/cuda/tools/stub/cuda_runtime.h). Not a substitute for nvcc.
#   LLVM_CLANG=/opt/homebrew/opt/llvm/bin/clang++ scripts/tensor_cuda_ptx_check.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${LLVM_CLANG:-/opt/homebrew/opt/llvm/bin/clang++}"
D="$ROOT/src/tensor/cuda"
OUT="${TMPDIR:-/tmp}/tensor_cuda_ptx"; mkdir -p "$OUT"
STUB=(-include "$D/tools/stub/cuda_runtime.h" -I"$D/tools/stub")
for arch in sm_90 sm_120; do
  "$CC" -x cuda -D__CUDACC__ --cuda-gpu-arch=$arch -nocudainc -nocudalib --cuda-device-only -O2 -std=c++17 -Wall -Werror \
    -S -Xclang -target-feature -Xclang +ptx87 "${STUB[@]}" -I"$D" "$D/tc_host.cu" -o "$OUT/tc_$arch.ptx"
  echo "$arch: $(grep -c '\.entry ' "$OUT/tc_$arch.ptx") kernels; local-memory frames:"
  awk '/\.entry /{n=$0; sub(/\(.*/,"",n); sub(/.*entry /,"",n)} /local_depot[0-9]+\[/{print "   ", n, $NF}' "$OUT/tc_$arch.ptx"
done
"$CC" -x cuda -D__CUDACC__ --cuda-gpu-arch=sm_90 -nocudainc -nocudalib --cuda-host-only -std=c++17 -Wall -Werror -fsyntax-only "${STUB[@]}" -I"$D" "$D/tc_host.cu"
echo "host side: OK"
