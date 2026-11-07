#!/bin/bash
# M9 GPU capture replay: build the standalone kernel harness and run it with a short GPU
# lock hold. Pod only. Usage (on the pod):
#   scripts/rv64_m9/gpu_replay_bench.sh build
#   scripts/rv64_m9/gpu_replay_bench.sh run DUMP_DIR [ITERS] [SEGMENT|-1] [GPU]
# Build artifacts go to /workspace/m3/src/m9-gpu-replay/build-m9 (delete when done).
set -euo pipefail
ROOT=/workspace/m3/src/m9-gpu-replay
OUT=$ROOT/build-m9
NVCC=/usr/local/cuda/bin/nvcc
case "${1:-}" in
  build)
    mkdir -p "$OUT"
    flock -w 3600 /workspace/m3/locks/build.3.lock \
      "$NVCC" -O3 -std=c++17 -arch=sm_120 -lineinfo -DM9_STANDALONE \
        "$ROOT/src/backends/cuda/native/rv64/m9_gpu_replay.cu" -o "$OUT/m9_gpu_replay"
    echo "built $OUT/m9_gpu_replay";;
  run)
    dump="$2"; iters="${3:-10}"; seg="${4:--1}"; gpu="${5:-0}"
    # <= 5 min hold; the harness holds GPU memory only while it runs.
    CUDA_VISIBLE_DEVICES="$gpu" flock -w 3600 /workspace/m3/locks/gpu.lock \
      timeout 300 "$OUT/m9_gpu_replay" "$dump" "$iters" "$seg";;
  *) echo "usage: $0 build | run DUMP_DIR [ITERS] [SEGMENT] [GPU]"; exit 2;;
esac
