#!/bin/bash
# build.sh <srcname> <outname> [step] [optimize] [lock]  build-throttled (blocking flock on build.<lock>.lock)
set -o pipefail
src=/workspace/m3/src/$1; out=/workspace/m3/build/m6-capture/$2; step=${3:-rv64-capture-bench}; opt=${4:-ReleaseFast}; lk=${5:-1}
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
mkdir -p $out; cd $src
s=$(date +%s)
flock -w 7200 /workspace/m3/locks/build.$lk.lock nice -n 5 /workspace/zig/zig build $step -Doptimize=$opt -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Dimplementation-commit=${COMMIT} -Dimplementation-tree=${TREE} -Dimplementation-dirty=false -j16 --cache-dir /workspace/m3/build/m6-capture/zcache-$1 --prefix $out > $out/zig.log 2>&1
rc=$?
tail -40 $out/zig.log
echo STEP $step rc=$rc $(($(date +%s)-s))s
ls -la $out/bin
