#!/bin/bash
# k-merkle pipeline 2 (pod). STEPS (default "img gates ab") selects stages; pipe 3 = STEPS="gate5 ab" after the
# rebase onto integrate 786429aca (harness-only changes). img2 (img1 TUs + circuit_fill_chain.cu with chain_flow removed) -> drop img1 ->
# gate-3 default 24628607 -> gate-4 26235156 with MERKLE_FUSED=1 + 2^28 chunk knobs + assignment graph ->
# 3+3 ab-fused and ab-chunk on img2, each started only in a quiet window (no foreign compiler/receiver, load < 8)
# and retried when the harness's quiet admission times out.
set -u
S=m8-k-merkle; R=/workspace/m3/runs/$S; SRC=/workspace/m3/src/$S; B=/workspace/m3/build/$S; RT=$B/img2/runtime.json
C=$(cat $SRC/.m3-commit); ST=$R/${PIPE:-pipe2}.status; STEPS=${STEPS:-"img gates ab"}; K=$SRC/vectors/reports/rv64-m8-20261106/k-merkle
log() { echo "$(date -u +%FT%TZ) $*" >> $ST; }
log start commit=$C
cd $SRC
has() { case " $STEPS " in *" $1 "*) return 0;; esac; return 1; }
if has img; then
flock /workspace/m3/locks/build.2.lock python3 $K/compose_image.py $SRC $B/img2 rv64/trace.cu rv64/fri.cu rv64/pcs_native.cu \
  rv64/circuit_fill_chain.cu > $R/img2.log 2>&1 || { log img2-failed; exit 1; }
log img2 $(grep -o '"library_sha256": "[0-9a-f]*"' $B/img2/image.json)
rm -f $B/img2/objects/*.o; rm -rf $B/img1
fi
waitfree() {
  while true; do
    u=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | sort -n | tail -1)
    free=$(df -BG --output=avail /workspace | tail -1 | tr -dc 0-9)
    [ "$u" -lt 2048 ] && [ "$free" -ge 4 ] && break; sleep 30
  done
}
waitquiet() {  # 6 consecutive 10 s samples: 1-min load < 8 and no compiler/receiver process
  n=0
  while [ $n -lt 6 ]; do
    l=$(cut -d' ' -f1 /proc/loadavg)
    if awk -v l=$l 'BEGIN{exit !(l < 8)}' && ! pgrep -x 'zig|nvcc|cicc|ptxas|rv64-word16-ethereum-recursion-receiver' >/dev/null; then n=$((n+1)); else n=0; fi
    sleep 10
  done
}
waitfree; log gpus-free
if has gate5; then
bash scripts/rv64_gate.sh --stream $S --block 24628607 --out $R/gate-5-def-24628607 --source-commit $C --runtime $RT > $R/gate-5.log 2>&1
rc=$?; log gate-5-def-24628607 rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
fi
if has gates; then
bash scripts/rv64_gate.sh --stream $S --block 24628607 --out $R/gate-3-def-24628607 --source-commit $C --runtime $RT > $R/gate-3.log 2>&1
rc=$?; log gate-3-def-24628607 rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
bash scripts/rv64_gate.sh --stream $S --block 26235156 --out $R/gate-4-on-26235156 --source-commit $C --runtime $RT \
  --env STWO_RV64_M8_MERKLE_FUSED=1 --env STWO_RV64_PCS_STREAM_CHUNK_WORDS=268435456 --env STWO_RV64_TRACE_STREAM_CHUNK_WORDS=268435456 \
  --env STWO_RV64_OUTER_ASSIGNMENT_GRAPH=1 > $R/gate-4.log 2>&1
rc=$?; log gate-4-on-26235156 rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
fi
rm -rf $SRC/.zig-cache
get() { python3 -c "import json,sys;print(json.load(open('$RT'))['assets'][sys.argv[1]])" $1; }
has ab || { log DONE; exit 0; }
for ab in ab-fused ab-chunk; do
  for try in 1 2 3 4 5 6 7 8; do
    out=$R/$ab-img2-${PIPE:-pipe2}-t$try
    waitfree; waitquiet; log $ab try=$try quiet
    python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $C \
      --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
      --library $(get library) --sparse $(get sparse) --observer $(get observer) --process-budget-guard $(get process_budget_guard) \
      --native-hooks-commit 95e3d7e15 --device-hooks-commit 95e3d7e15 \
      --preset $K/$ab.json --block 24628607 --out $out-manifest.json > $out-prepare.log 2>&1
    python3 scripts/rv64_m7_integration_stack.py run --manifest $out-manifest.json --out $out > $out.log 2>&1
    rc=$?; log $ab try=$try rc=$rc
    [ $rc -eq 0 ] && break
    grep -rqs "quiet admission timed out" $out/ || { log $ab non-quiet-failure; break; }
  done
done
log DONE
