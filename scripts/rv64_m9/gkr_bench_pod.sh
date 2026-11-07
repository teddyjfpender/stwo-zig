#!/bin/bash
# M9 outer-GKR kernel bench on a DEV pod (never the 2x5090). Usage on the pod:
#   bash scripts/rv64_m9/gkr_bench_pod.sh build            # nvcc under build.N.lock, no GPU
#   bash scripts/rv64_m9/gkr_bench_pod.sh run <args...>    # one run under gpu.lock (<= 15 min hold)
# Output: one JSON line per run on stdout. Build dir /workspace/m3/build/m9-gkr-bench (delete when done).
set -euo pipefail
SRC=$(cd "$(dirname "$0")/../.." && pwd)
OUT=/workspace/m3/build/m9-gkr-bench
NVCC=${NVCC:-/usr/local/cuda/bin/nvcc}
case "${1:-}" in
build)
  mkdir -p "$OUT"
  D="$SRC/src/backends/cuda/native/rv64/bench"
  F=(-O3 -std=c++17 -arch=sm_120 -lineinfo -I "$SRC/src/backends/cuda/native" -Xcompiler -fopenmp -Xptxas -warn-spills)
  flock -w 3600 /workspace/m3/locks/build.1.lock bash -c '
    set -e; D=$1; OUT=$2; NVCC=$3; shift 3
    for u in m9_gkr_bench fused_kind2 fused_kind3 fused_kind4 fused_kind6; do
      "$NVCC" "$@" -c "$D/$u.cu" -o "$OUT/$u.o" > "$OUT/$u.log" 2>&1 & done; wait
    "$NVCC" -arch=sm_120 -Xcompiler -fopenmp "$OUT"/*.o -o "$OUT/m9_gkr_bench"' _ "$D" "$OUT" "$NVCC" "${F[@]}"
  grep -h 'spill\|error' "$OUT"/*.log | sort | uniq -c | head -30; ls -la "$OUT/m9_gkr_bench"
  ;;
run)
  shift
  OMP_NUM_THREADS=${OMP_NUM_THREADS:-24} timeout 840 flock -w 3600 /workspace/m3/locks/gpu.lock "$OUT/m9_gkr_bench" "$@"
  ;;
*) echo "usage: $0 build|run args" >&2; exit 2 ;;
esac
