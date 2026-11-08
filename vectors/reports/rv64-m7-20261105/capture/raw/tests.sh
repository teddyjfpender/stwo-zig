#!/bin/bash
# tests.sh <srcname> <lock> suite...   ReleaseSafe, build-throttled (blocking flock)
src=/workspace/m3/src/$1; lk=$2; shift 2
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
cd $src
for t in "$@"; do s=$(date +%s)
flock -w 7200 /workspace/m3/locks/build.$lk.lock nice -n 5 /workspace/zig/zig build $t -Doptimize=ReleaseSafe -Dcpu=x86_64_v4+sha -Dimplementation-commit=$COMMIT -Dimplementation-tree=$TREE -Dimplementation-dirty=false -j16 $EXTRA --cache-dir /workspace/m3/build/m7-capture/testcache 2>&1 | tail -60
echo STEP $t rc=${PIPESTATUS[0]} $(($(date +%s)-s))s; done
