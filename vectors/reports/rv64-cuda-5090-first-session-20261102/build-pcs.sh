#!/usr/bin/env bash
set -euo pipefail
cd /workspace/stwo-zig
export PATH=/usr/local/cuda/bin:$PATH
B=/workspace/rv64-gpu-session/build
R=/workspace/rv64-gpu-session/results
F=(-O3 -std=c++17 -lineinfo -gencode arch=compute_120,code=sm_120 -Isrc/backends/cuda/native)
for entry in transform/n2b transform/b2n_retained transform/lde commitment/merkle commitment/progressive fri/fold fri/final pow/search; do
 name=${entry//\//-}
 nvcc "${F[@]}" -c "src/backends/cuda/native/$entry.cu" -o "$B/$name.o" > "$R/$name-build.log" 2>&1
done
nvcc "${F[@]}" tests/cuda/rv64/pcs_calibration.cu "$B/context.o" "$B/transform-n2b.o" "$B/transform-lde.o" "$B/commitment-merkle.o" "$B/commitment-progressive.o" "$B/fri-fold.o" "$B/pow-search.o" -Xcompiler=-pthread -ldl -o "$B/pcs-calibration" > "$R/pcs-calibration-build.log" 2>&1
nvcc "${F[@]}" tests/cuda/native_transform_smoke.cpp "$B/context.o" "$B/transform-n2b.o" "$B/transform-b2n_retained.o" "$B/transform-lde.o" -Xcompiler=-pthread -ldl -o "$B/transform-smoke" > "$R/transform-smoke-build.log" 2>&1
nvcc "${F[@]}" tests/cuda/native_blake2s_commitment_smoke.cpp "$B/context.o" "$B/commitment-merkle.o" "$B/commitment-progressive.o" -Xcompiler=-pthread -ldl -o "$B/blake-smoke" > "$R/blake-smoke-build.log" 2>&1
nvcc "${F[@]}" tests/cuda/native_fri_pow_smoke.cpp "$B/context.o" "$B/fri-fold.o" "$B/fri-final.o" "$B/pow-search.o" -Xcompiler=-pthread -ldl -o "$B/fri-pow-smoke" > "$R/fri-pow-smoke-build.log" 2>&1
printf 'PCS_BUILD_PASS\n'
