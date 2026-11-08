#!/bin/bash
# M5 integrate: unit/qualification steps of every merged stream on the merged tree (pod, CPU only, build lock).
set -u
SRC=/workspace/m3/src/m5-integrate; OUT=/workspace/m3/runs/m5-integrate/tests; mkdir -p $OUT
ZIG=/workspace/zig/zig; export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
C=$(cat $SRC/.m3-commit-full)
ID="-Dimplementation-commit=$C -Dimplementation-tree=$(cat $SRC/.m3-tree) -Dimplementation-dirty=false"
cd $SRC
lock() { flock -w 3600 /workspace/m3/locks/build.$((RANDOM%3+1)).lock "$@"; }
t() { name=$1; shift; t0=$(date +%s); lock "$@" > $OUT/$name.log 2>&1; rc=$?; echo "$name exit=$rc $(( $(date +%s)-t0 ))s $(grep -E 'tests passed|passed;|Build Summary' $OUT/$name.log | tail -1)"; }
for step in test-riscv64-m5-rootverify test-riscv64-m5-vk-table test-riscv64-outer-gkr test-riscv64-word16-execution-source test-riscv64-word16-execution-prepared; do
  t $step $ZIG build $step -Doptimize=ReleaseSafe $ID --cache-dir $SRC/.zig-cache --summary all
done
t fused-blake $ZIG test -OReleaseFast src/frontends/circuit/fused_blake_test_root.zig --cache-dir $SRC/.zig-cache
t security-candidate $ZIG test -OReleaseSafe src/integrations/riscv_cpu/rv64_om31_security_candidate_test_root.zig --cache-dir $SRC/.zig-cache
echo TESTS_DONE
