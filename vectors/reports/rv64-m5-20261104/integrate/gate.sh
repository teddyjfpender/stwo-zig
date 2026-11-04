#!/bin/bash
# M5 integrate gate (pod). Serial, stops at the first failure. Dev blocks only, then ONE scale probe.
#   bash gate.sh [steps...]
# steps:
#   a-seed a-warm a-counters      (a) proof-neutral config, old format: byte-identical to M4 (= M3) receipts
#   a-nsys                        (a) one warm service pass under nsys (GPU busy; timing not quotable)
#   a22-warm                      (a) same, with the 22 GiB device-arena carve (device-peak gate)
#   b-bench b-warm                (b) M5 format: canonical outer profile (uniform-v1), binary folds, full-tree receiver
#   b-root                        (b) derive-vk-tables once, root-only verify (pinned), --audit, both corpora (CPU only)
#   scale                         ONE scale probe on 24697070 with the chosen default config
set -euo pipefail
cd /workspace/m3/src/m5-integrate
S=m5-integrate
R=/workspace/m3/runs/$S
REF=/workspace/m3/runs/integrate
BIN=/workspace/m3/build/$S/zig-out/bin
RECV=$BIN/rv64-word16-ethereum-recursion-receiver
ENV=(--env STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1 --env STWO_RV64_GPU_CPU_REPLAY=1
     --env STWO_RV64_CORE_SINGLE_STREAM=1 --env STWO_RV64_DEVICE_ARENA=1)
ENV22=(--env STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1 --env STWO_RV64_GPU_CPU_REPLAY=1
       --env STWO_RV64_CORE_SINGLE_STREAM=1 --env STWO_RV64_DEVICE_ARENA=22G)
CANON=m5_outer_canonical_r1_b2_q108_p20_fold4_v1
D="python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream $S"
steps=("$@"); [ ${#steps[@]} -eq 0 ] && steps=(a-seed a-warm a-counters b-bench b-warm b-root)
for s in "${steps[@]}"; do
  echo "STEP $s start $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
  case $s in
    a-seed)  $D --repeat 1 --tag a1-seed --store fresh "${ENV[@]}" --receive none ;;
    a-warm)  $D --repeat 2 --tag a2-warm --store reuse --warm "${ENV[@]}" --receive all ;;
    a22-warm) $D --repeat 2 --tag a3-warm22 --store reuse --warm "${ENV22[@]}" --receive first ;;
    a-nsys)  $D --repeat 1 --tag a5-nsys --store reuse --warm --nsys "${ENV[@]}" --receive none ;;
    a-counters)
      for b in 26235156 24628607; do
        python3 scripts/rv64_m3_pod.py prove $b --gpus 2 --stream $S --tag a4-counters --counters --smaps \
          --reference $REF/$b-2gpu-scale/receipt.json "${ENV[@]}"
      done ;;
    b-bench)
      # receiver inherits the caller env, the producer gets --env: set the profile in both.
      for b in 26235156 24628607; do
        STWO_RV64_OUTER_PROFILE=$CANON python3 scripts/rv64_m3_pod.py bench $b --gpus 2 --stream $S --tag b1-canon \
          "${ENV[@]}" --env STWO_RV64_OUTER_PROFILE=$CANON
      done ;;
    b-warm)  STWO_RV64_OUTER_PROFILE=$CANON $D --repeat 2 --tag b2-canon-warm --store reuse --warm "${ENV[@]}" \
               --env STWO_RV64_OUTER_PROFILE=$CANON --receive first ;;
    b-root)  STWO_RV64_OUTER_PROFILE=$CANON bash vectors/reports/rv64-m5-20261104/integrate/rootonly.sh ;;
    scale)
      python3 scripts/rv64_m3_pod.py bench 24697070 --gpus 2 --stream $S --tag s1-scale --allow-scale-up \
        --reference $REF/24697070-2gpu-scale/receipt.json "${ENV[@]}" ;;
  esac
  echo "STEP $s done $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
done
echo GATE_DONE
