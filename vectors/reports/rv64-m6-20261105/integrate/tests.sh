#!/bin/bash
# M6 integrate: unit/qualification steps of every merged stream on the merged tree (pod, CPU only, build lock).
set -u
SRC=/workspace/m3/src/m6-integrate; OUT=/workspace/m3/runs/m6-integrate/tests; mkdir -p $OUT
ZIG=/workspace/zig/zig; export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global TMPDIR=/workspace/m3/tmp
C=$(cat $SRC/.m3-commit-full)
ID="-Dimplementation-commit=$C -Dimplementation-tree=$(cat $SRC/.m3-tree) -Dimplementation-dirty=false"
cd $SRC
lock() { flock -w 3600 /workspace/m3/locks/build.$((RANDOM%3+1)).lock "$@"; }
t() { name=$1; shift; t0=$(date +%s); lock "$@" > $OUT/$name.log 2>&1; rc=$?; echo "$name exit=$rc $(( $(date +%s)-t0 ))s $(grep -E 'tests passed|passed;|Build Summary' $OUT/$name.log | tail -1)"; }
# riscv_cuda-scoped steps (sched ready_dag/streaming, hint-tape chain plan, native-stream replay): run from that build root.
for step in test-rv64-recursion-ready test-rv64-gkr-plan; do
  t $step sh -c "cd $SRC/src/integrations/riscv_cuda && $ZIG build $step -Doptimize=ReleaseSafe --cache-dir $SRC/.zig-cache --summary all"
done
steps=("$@"); [ ${#steps[@]} -eq 0 ] && steps=(test-riscv64-m5-rootverify test-riscv64-m5-canon-native test-riscv64-native-gkr test-riscv64-execution test-riscv64-om31-outer)
for step in "${steps[@]}"; do
  t $step $ZIG build $step -Doptimize=ReleaseSafe $ID --cache-dir $SRC/.zig-cache --summary all
done
t security-candidate $ZIG test -OReleaseSafe --dep stwo_core -Mroot=src/integrations/riscv_cpu/rv64_om31_security_candidate_test_root.zig -Mstwo_core=src/core/mod.zig --cache-dir $SRC/.zig-cache
python3 -m unittest tests/scripts/rv64_sync_lint_test.py > $OUT/sync-lint-unittest.log 2>&1; echo "sync-lint-unittest exit=$? $(tail -1 $OUT/sync-lint-unittest.log)"
python3 scripts/rv64_sync_lint.py check > $OUT/sync-lint-check.log 2>&1; echo "sync-lint-check exit=$? $(tail -1 $OUT/sync-lint-check.log)"
python3 scripts/rv64_progress.py check > $OUT/progress-check.log 2>&1; echo "progress-check exit=$? $(tail -1 $OUT/progress-check.log)"
echo TESTS_DONE
