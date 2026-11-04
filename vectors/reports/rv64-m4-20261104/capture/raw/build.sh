#!/bin/bash
# build.sh <srcname> <outname> [step]   CPU capture binary, ReleaseFast x86_64_v4+sha, build-throttled
set -o pipefail
src=/workspace/m3/src/$1; out=/workspace/m3/build/m4-capture/$2; step=${3:-rv64-word16-ethereum-gkr}
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
mkdir -p $out; cd $src
s=$(date +%s)
flock -w 7200 /workspace/m3/locks/build.$((RANDOM%3+1)).lock nice -n 5 /workspace/zig/zig build $step -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Dimplementation-commit=$COMMIT -Dimplementation-tree=$TREE -Dimplementation-dirty=false -j16 --cache-dir $src/.zig-cache --prefix $out 2>&1 | tail -40
rc=$?
echo STEP $step rc=$rc $(($(date +%s)-s))s
ls -la $out/bin
