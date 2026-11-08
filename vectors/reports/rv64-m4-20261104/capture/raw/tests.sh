#!/bin/bash
# tests.sh <srcname> suite...   ReleaseSafe, build-throttled
src=/workspace/m3/src/$1; shift
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
cd $src
for t in "$@"; do s=$(date +%s)
flock -w 7200 /workspace/m3/locks/build.$((RANDOM%3+1)).lock nice -n 5 /workspace/zig/zig build $t -Doptimize=ReleaseSafe -Dcpu=x86_64_v4+sha -Dimplementation-commit=$COMMIT -Dimplementation-tree=$TREE -Dimplementation-dirty=false -j16 --cache-dir /root/m4-capture-cache/test 2>&1 | tail -25
echo STEP $t rc=${PIPESTATUS[0]} $(($(date +%s)-s))s; done
