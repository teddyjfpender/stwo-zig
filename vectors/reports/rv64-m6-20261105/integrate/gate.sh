#!/bin/bash
# M6 integrate gate (pod). Serial, stops at the first failure. Dev blocks only, then ONE scale probe.
#   bash gate.sh [steps...]
# steps (GPU steps take the GPU lock themselves, one hold per step, <= ~25 min):
#   m5-warm     M5 integrate binaries in the same session (baseline A/B; RV64_NATIVE_SCHEDULE='{}', old drivers refuse new fields)
#   a-warm      (a) M6 pipeline, OLD format, resident service, --store none, 3 rounds (rounds 2-3 warm); fresh receiver on round 1
#   a-trace     (a) one more service pass with enqueue's LD_PRELOAD sync/launch tracer (counts per node; timing not quoted)
#   a-bench     (a) one-shot bench (proofs for the root-only receiver + full-tree verify time)
#   b-bench     (b) NEW format: native v2-strict + diet k4-cap3 outer profile, one-shot bench + full-tree receiver
#   c-bench/c-warm/c-root  (c) diet k4-cap3 outer profile on the flat (M5) native format: the candidate default
#   b-warm      (b) same format, resident service, --store none, 3 rounds, fresh receiver on round 1
#   a-root/b-root  root-only receiver (fold-v3 rootonly recipe): derive once, pinned root-only, --audit, corpora (CPU only)
#   scale       ONE scale probe on 24697070 with the chosen default config
set -euo pipefail
S=m6-integrate
SRC=/workspace/m3/src/$S
cd $SRC
R=/workspace/m3/runs/$S
REF=/workspace/m3/runs/integrate
BIN=/workspace/m3/build/$S/zig-out/bin
K4=m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1
NV=m6-native-v2-strict
BENV=(--env STWO_RV64_OUTER_PROFILE=$K4 --env STWO_RV64_NATIVE_VERSION=$NV)
D="python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream $S"
TRACE=/workspace/m3/build/m6-enqueue/shim/librv64_sync_trace.so
export TMPDIR=/workspace/m3/tmp
mkdir -p $R $TMPDIR
# the harness (rv64_m3_pod.acquire_gpu_lock) takes /workspace/m3/locks/gpu.lock itself for the producer: do not wrap it
lock() { "$@"; }
steps=("$@"); [ ${#steps[@]} -eq 0 ] && steps=(m5-warm a-warm b-bench b-warm)
for s in "${steps[@]}"; do
  echo "STEP $s start $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
  case $s in
    m5-warm) RV64_NATIVE_SCHEDULE='{}' lock $D --build-stream m5-integrate --repeat 3 --tag m5-ab --store none --receive none ;;
    d-final) lock $D --repeat 3 --tag d1-default --store none --receive first ;;   # harness default = config (c) (DEFAULT_PRODUCER_ENV)
    a-final) lock $D --repeat 3 --tag a5-final --store none --env STWO_RV64_OUTER_PROFILE=r1 --receive first ;;
    a-warm)  lock $D --repeat 3 --tag a1-warm --store none --receive first ;;
    a22-warm) lock $D --repeat 3 --tag a4-warm22 --store none --env STWO_RV64_DEVICE_ARENA=22G --receive none ;;
    a-trace) mkdir -p $R/a2-trace; RV64_SYNC_TRACE_OUT=$R/a2-trace LD_PRELOAD=$TRACE lock $D --repeat 2 --tag a2-trace --store none --receive none ;;
    a-bench)
      for b in 26235156 24628607; do
        lock python3 scripts/rv64_m3_pod.py bench $b --gpus 2 --stream $S --tag a3-bench --reference $REF/$b-2gpu-scale/receipt.json
      done ;;
    b-bench)
      # receiver inherits the caller env, the producer gets --env: set both selectors in both.
      for b in 26235156 24628607; do
        STWO_RV64_OUTER_PROFILE=$K4 STWO_RV64_NATIVE_VERSION=$NV lock python3 scripts/rv64_m3_pod.py bench $b --gpus 2 --stream $S --tag b1-bench "${BENV[@]}"
      done ;;
    c-bench)
      for b in 26235156 24628607; do
        STWO_RV64_OUTER_PROFILE=$K4 lock python3 scripts/rv64_m3_pod.py bench $b --gpus 2 --stream $S --tag c1-bench --env STWO_RV64_OUTER_PROFILE=$K4
      done ;;
    c-warm)  STWO_RV64_OUTER_PROFILE=$K4 lock $D --repeat 3 --tag c2-warm --store none --env STWO_RV64_OUTER_PROFILE=$K4 --receive first ;;
    c-root)  FORMAT=c TAG=c1-bench CORPUS=${CORPUS:-1} bash vectors/reports/rv64-m6-20261105/integrate/rootonly.sh ;;
    b-warm)  STWO_RV64_OUTER_PROFILE=$K4 STWO_RV64_NATIVE_VERSION=$NV lock $D --repeat 3 --tag b2-warm --store none "${BENV[@]}" --receive first ;;
    a-root)  FORMAT=a TAG=a3-bench CORPUS=${CORPUS:-1} bash vectors/reports/rv64-m6-20261105/integrate/rootonly.sh ;;
    b-root)  FORMAT=b TAG=b1-bench CORPUS=${CORPUS:-1} bash vectors/reports/rv64-m6-20261105/integrate/rootonly.sh ;;
    b-corpus|c-corpus)
      # profiles negative corpus v4, full-tree receiver (fresh CPU-only process per case) on a new-format config;
      # NV03/DW07 cross-format cases use the old-format (M3 = M5 default bytes) proof of the same block as --alt-format-run.
      cfg=${s%%-*}; tag=$([ $cfg = b ] && echo b1-bench || echo c1-bench)
      export CUDA_VISIBLE_DEVICES= STWO_RV64_GPU_PCS_HELPER=/bin/false; unset STWO_ZIG_RV64_SETUP_CACHE
      if [ $cfg = b ]; then export STWO_RV64_NATIVE_VERSION=$NV; else unset STWO_RV64_NATIVE_VERSION; fi
      for b in 26235156 24628607; do o=$([ $b = 26235156 ] && echo 24628607 || echo 26235156)
        STWO_RV64_OUTER_PROFILE=$K4 python3 -I scripts/rv64_m5_negative_corpus.py run --format m5-audit \
          --run $R/$b-2gpu-$tag --donor $R/$o-2gpu-$tag --alt-format-run $REF/$b-2gpu-scale --receiver ${RECEIVER:-$BIN/rv64-word16-ethereum-recursion-receiver} \
          --jobs ${JOBS:-3} --work /workspace/m3/scratch/m6-integrate/corpus-$cfg --out $R/$b-corpus-v4-$cfg-fulltree.json > $R/$b-corpus-$cfg.log 2>&1 || true
        echo "corpus $cfg $b: $(tail -1 $R/$b-corpus-$cfg.log)"
      done
      rm -rf /workspace/m3/scratch/m6-integrate/corpus-$cfg ;;
    scale)
      lock python3 scripts/rv64_m3_pod.py bench 24697070 --gpus 2 --stream $S --tag s1-scale --allow-scale-up \
        --reference $REF/24697070-2gpu-scale/receipt.json ${SCALE_ARGS:-} ;;
  esac
  echo "STEP $s done $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
done
echo GATE_DONE
