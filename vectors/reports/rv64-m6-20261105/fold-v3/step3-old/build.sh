#!/bin/bash
# fold-v3: build the CPU-only receiver (+ optional unit test step) under a build lock.
set -u
SRC=/workspace/m3/src/m6-fold-v3; B=/workspace/m3/build/m6-fold-v3${BSUFFIX:-}; R=/workspace/m3/runs/m6-fold-v3
mkdir -p $B $R
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
lock() { flock -w 3600 /workspace/m3/locks/build.$((RANDOM%3+1)).lock "$@"; }
what=${1:-receiver}
t0=$(date +%s)
if [ "$what" = receiver ]; then
  cd $SRC/src/integrations/riscv_cuda && lock /workspace/zig/zig build build-rv64-ethereum-recursion-receiver -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Doptimize=ReleaseFast --cache-dir $SRC/.zig-cache --prefix $B/zig-out
  rc=$?
  sha256sum $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver
else
  ID="-Dimplementation-commit=$(cat $SRC/.m3-commit-full) -Dimplementation-tree=$(cat $SRC/.m3-tree) -Dimplementation-dirty=false"; cd $SRC && lock /workspace/zig/zig build $what -Doptimize=ReleaseSafe $ID --cache-dir $SRC/.zig-cache --summary all
  rc=$?
fi
echo "BUILD $what exit=$rc $(( $(date +%s)-t0 ))s"
