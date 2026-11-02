#!/usr/bin/env bash
set -euo pipefail
cd /workspace/stwo-zig
export PATH=/usr/local/cuda/bin:$PATH
B=/workspace/rv64-gpu-session/build
R=/workspace/rv64-gpu-session/results
mkdir -p "$B" "$R"
FLAGS=(-O3 -std=c++17 -lineinfo -gencode arch=compute_120,code=sm_120 -Isrc/backends/cuda/native -I/usr/local/cuda/include)
nvcc "${FLAGS[@]}" -c src/backends/cuda/native/runtime/context.cu -o "$B/context.o" > "$R/context-build.log" 2>&1
nvcc "${FLAGS[@]}" -c src/backends/cuda/native/rv64/gkr.cu -o "$B/gkr.o" > "$R/gkr-build.log" 2>&1
nvcc "${FLAGS[@]}" -c src/backends/cuda/native/rv64/round.cu -o "$B/round.o" > "$R/round-build.log" 2>&1
nvcc "${FLAGS[@]}" -c src/backends/cuda/native/rv64/tail.cu -o "$B/tail.o" > "$R/tail-build.log" 2>&1
g++ -O3 -std=c++17 -Itests/cuda/rv64/host_include -Isrc/backends/cuda/native -c tests/cuda/rv64/numerical_bridge.cpp -o "$B/oracle.o" > "$R/oracle-build.log" 2>&1
nvcc "${FLAGS[@]}" tests/cuda/rv64/resident_smoke.cu "$B/context.o" "$B/gkr.o" -Xcompiler=-pthread -ldl -o "$B/resident-smoke" > "$R/resident-link.log" 2>&1
for driver in sumcheck tail; do
 nvcc "${FLAGS[@]}" "tests/cuda/rv64/${driver}_smoke.cu" "$B/context.o" "$B/gkr.o" "$B/round.o" "$B/tail.o" "$B/oracle.o" -Xcompiler=-pthread -ldl -o "$B/${driver}-smoke" > "$R/${driver}-link.log" 2>&1
done
printf 'BUILD_GATES_PASS\n'
"$B/resident-smoke" 1 10 > "$R/resident-first.jsonl" 2> "$R/resident-first.stderr"
"$B/sumcheck-smoke" 1 10 > "$R/sumcheck-first.jsonl" 2> "$R/sumcheck-first.stderr"
"$B/tail-smoke" 1 > "$R/tail-first.jsonl" 2> "$R/tail-first.stderr"
printf 'FIRST_DEVICE_GATES_PASS\n'
