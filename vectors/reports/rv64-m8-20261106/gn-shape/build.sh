#!/bin/bash
# gn-shape: usage build.sh <n> <zig step> (ReleaseSafe, build lock 3)
S=m8-gn-shape
cd /workspace/m3/src/$S/src/integrations/riscv_cuda
LOG=/workspace/m3/runs/$S/zig-$1.log
flock /workspace/m3/locks/build.3.lock env ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global /workspace/zig/zig build $2 -Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Doptimize=ReleaseSafe --cache-dir /workspace/m3/src/$S/.zig-cache --prefix /workspace/m3/build/$S/zig-out --color off 2>&1 | tr -d "\\000" > $LOG
echo EXIT $? >> $LOG
