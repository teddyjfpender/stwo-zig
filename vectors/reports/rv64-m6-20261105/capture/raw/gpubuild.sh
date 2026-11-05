#!/bin/bash
# gpubuild.sh <srcname> <lock>: production driver (rv64-word16-ethereum-gpu-combined) only, M3 harness flags
set -o pipefail
src=/workspace/m3/src/$1; lk=$2; out=/workspace/m3/build/m6-capture
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
mkdir -p $out/logs; cd $src/src/integrations/riscv_cuda
s=$(date +%s)
flock -w 7200 /workspace/m3/locks/build.$lk.lock nice -n 5 /workspace/zig/zig build build-rv64-ethereum-gpu-combined -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Doptimize=ReleaseFast --cache-dir $src/.zig-cache --prefix $out/zig-out > $out/logs/build-rv64-ethereum-gpu-combined.log 2>&1
rc=$?
tail -30 $out/logs/build-rv64-ethereum-gpu-combined.log
echo STEP gpu-combined rc=$rc $(($(date +%s)-s))s
sha256sum $out/zig-out/bin/* 2>/dev/null
