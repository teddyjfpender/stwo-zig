#!/usr/bin/env bash
set -euo pipefail
mkdir -p /workspace/stwo-zig-v7
tar --no-same-owner -xzf /workspace/source-v7.tar.gz -C /workspace/stwo-zig-v7
cd /workspace/stwo-zig-v7
export STWO_CUDA_AOT_CUBIN_IMPORT_ROOT=/workspace/native-cubins
export STWO_CUDA_ARCHIVE_CACHE=/workspace/cuda-archive-cache
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH:-}
/opt/zig/zig-x86_64-linux-0.15.2/zig build stwo-cairo-cuda \
  -Doptimize=ReleaseFast \
  -Dimplementation-commit=214080ed64d4df5242effb3c3ef235c661bf8529 \
  -Dimplementation-tree=da8e3336a9014ff20476e95765c0cf4dd81224db \
  -Dimplementation-dirty=true \
  -Dimplementation-dirty-content-sha256=5273326af1b8f60680f890fda8cd4c4293fac5d2b3ade32ee99314681722b9d3 \
  -Dcuda-nvcc=/usr/local/cuda/bin/nvcc \
  -Dcuda-host-cxx=/usr/bin/g++ \
  -Dcuda-host-runtime=/usr/lib/x86_64-linux-gnu/libstdc++.so.6 \
  -Dcuda-host-unwind-runtime=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1 \
  -Dcuda-ar=/usr/bin/ar \
  -Dcuda-home=/usr/local/cuda \
  -Dcuda-library-dir=/usr/local/cuda/lib64 \
  -Dcuda-arch=sm_90 \
  -Dcuda-build-jobs=12 -j2 --summary all
cp zig-out/bin/stwo-cairo-cuda /workspace/candidate-v7.bin
sha256sum /workspace/candidate-v7.bin
