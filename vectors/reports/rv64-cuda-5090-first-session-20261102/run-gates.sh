#!/usr/bin/env bash
set -euo pipefail
cd /workspace/stwo-zig
export PATH=/usr/local/cuda/bin:$PATH
B=/workspace/rv64-gpu-session/build
R=/workspace/rv64-gpu-session/results
FLAGS=(-O3 -std=c++17 -lineinfo -gencode arch=compute_120,code=sm_120 -Isrc/backends/cuda/native)
for driver in resident sumcheck; do
 if [ "$driver" = resident ]; then objects=("$B/context.o" "$B/gkr.o"); else objects=("$B/context.o" "$B/gkr.o" "$B/round.o" "$B/tail.o" "$B/oracle.o"); fi
 nvcc "${FLAGS[@]}" "tests/cuda/rv64/${driver}_smoke.cu" "${objects[@]}" -Xcompiler=-pthread -ldl -o "$B/${driver}-smoke" > "$R/${driver}-ordered-link.log" 2>&1
done
for driver in resident sumcheck tail; do
 args=(1 10); if [ "$driver" = tail ]; then args=(1); fi
 for tool in memcheck initcheck racecheck synccheck; do
  compute-sanitizer --tool "$tool" --error-exitcode 99 "$B/${driver}-smoke" "${args[@]}" > "$R/${driver}-${tool}.log" 2>&1
  printf 'PASS %s %s\n' "$driver" "$tool"
 done
done
for log in 2 3 4 8 9 10 16 20 22; do
 "$B/resident-smoke" 1 "$log" > "$R/resident-log${log}.jsonl" 2> "$R/resident-log${log}.stderr"
 printf 'PASS resident log %s\n' "$log"
done
for log in 2 3 4 8 9 10 16 20; do
 "$B/sumcheck-smoke" 1 "$log" > "$R/sumcheck-log${log}.jsonl" 2> "$R/sumcheck-log${log}.stderr"
 printf 'PASS sumcheck log %s\n' "$log"
done
"$B/tail-smoke" 1 > "$R/tail-final.jsonl" 2> "$R/tail-final.stderr"
printf 'ALL_DEVICE_GATES_PASS\n'
