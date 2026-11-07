#!/bin/bash
# k-merkle pipeline 1 (pod): img1 -> gate default 26235156 -> gate 24628607 with MERKLE_FUSED=1 + 2^28 chunk knobs
# + assignment graph + T2 real-node dump -> T2 dump replay (chain_run vs chain_flow<W>) -> 3+3 ab-fused -> 3+3 ab-chunk.
set -u
S=m8-k-merkle; R=/workspace/m3/runs/$S; SRC=/workspace/m3/src/$S; B=/workspace/m3/build/$S; RT=$B/img1/runtime.json
C=$(cat $SRC/.m3-commit); ST=$R/pipe1.status; K=$SRC/vectors/reports/rv64-m8-20261106/k-merkle
log() { echo "$(date -u +%FT%TZ) $*" >> $ST; }
log start commit=$C
until grep -q "^ENQ_EXIT" $R/img1.log 2>/dev/null; do sleep 30; done
grep -q "^IMG_EXIT=0" $R/img1.log || { log img1-failed; exit 1; }
log img1 $(grep -o '"library_sha256": "[0-9a-f]*"' $B/img1/image.json) $(grep ENQ_EXIT $R/img1.log)
rm -f $B/img1/objects/*.o
mkdir -p $R/bench && cp $SRC/vectors/reports/rv64-m8-20261106/T2-assignment-chain/chain_flow_bench.cu $R/bench/
( cd $R/bench && flock /workspace/m3/locks/build.3.lock /usr/local/cuda/bin/nvcc -O3 -std=c++17 -arch=sm_120 -lineinfo \
    -I$SRC/src/backends/cuda/native/rv64 chain_flow_bench.cu -o chain_flow_bench > build.log 2>&1 ) || log bench-build FAIL
waitfree() {
  while true; do
    u=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | sort -n | tail -1)
    free=$(df -BG --output=avail /workspace | tail -1 | tr -dc 0-9)
    [ "$u" -lt 2048 ] && [ "$free" -ge 4 ] && break; sleep 30
  done
}
waitfree; log gpus-free
cd $SRC
bash scripts/rv64_gate.sh --stream $S --block 26235156 --out $R/gate-1-def-26235156 --source-commit $C --runtime $RT > $R/gate-1.log 2>&1
rc=$?; log gate-1-def-26235156 rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
mkdir -p $R/dump
bash scripts/rv64_gate.sh --stream $S --block 24628607 --out $R/gate-2-on-24628607 --source-commit $C --runtime $RT \
  --env STWO_RV64_M8_MERKLE_FUSED=1 --env STWO_RV64_PCS_STREAM_CHUNK_WORDS=268435456 --env STWO_RV64_TRACE_STREAM_CHUNK_WORDS=268435456 \
  --env STWO_RV64_OUTER_ASSIGNMENT_GRAPH=1 --env STWO_RV64_M8_ASSIGNMENT_DUMP=$R/dump > $R/gate-2.log 2>&1
rc=$?; log gate-2-on-24628607 rc=$rc
rm -rf $SRC/.zig-cache
if [ -f $R/dump/assignment-node.bin ]; then
  log dump $(stat -c %s $R/dump/assignment-node.bin) bytes
  ( cd $R/bench && flock -w 3600 /workspace/m3/locks/gpu.lock env CUDA_VISIBLE_DEVICES=0 timeout 840 ./chain_flow_bench dump $R/dump/assignment-node.bin 7 > $R/bench/dump-bench.log 2>&1 )
  log bench rc=$?
else
  log dump MISSING
fi
[ $rc -eq 0 ] || { log STOP; exit 1; }
get() { python3 -c "import json,sys;print(json.load(open('$RT'))['assets'][sys.argv[1]])" $1; }
for ab in ab-fused ab-chunk; do
  waitfree
  python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $C \
    --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
    --library $(get library) --sparse $(get sparse) --observer $(get observer) --process-budget-guard $(get process_budget_guard) \
    --native-hooks-commit 95e3d7e15 --device-hooks-commit 95e3d7e15 \
    --preset $K/$ab.json --block 24628607 --out $R/$ab-manifest.json > $R/$ab-prepare.log 2>&1; log $ab-prepare rc=$?
  python3 scripts/rv64_m7_integration_stack.py run --manifest $R/$ab-manifest.json --out $R/$ab > $R/$ab.log 2>&1
  log $ab rc=$?
done
log DONE
