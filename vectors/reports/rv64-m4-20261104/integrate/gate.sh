#!/bin/bash
# M4 integrate gate (pod). Serial, stops at the first failure. Dev blocks only, then ONE scale probe.
#   bash gate.sh [steps...]   steps: seed cold warm nsys counters scale   (default: all, in order)
set -euo pipefail
cd /workspace/m3/src/m4-integrate
S=m4-integrate
R=/workspace/m3/runs/$S
REF=/workspace/m3/runs/integrate
ENV=(--env STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1 --env STWO_RV64_GPU_CPU_REPLAY=1
     --env STWO_RV64_CORE_SINGLE_STREAM=1 --env STWO_RV64_DEVICE_ARENA=1)
D="python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream $S"
steps=("$@"); [ ${#steps[@]} -eq 0 ] && steps=(seed cold warm nsys counters scale)
for s in "${steps[@]}"; do
  echo "STEP $s start $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
  case $s in
    seed)  $D --repeat 1 --tag g1-seed  --store fresh "${ENV[@]}" --receive all ;;
    cold)  $D --repeat 2 --tag g2-cold  --store reuse "${ENV[@]}" --receive none ;;
    warm)  $D --repeat 2 --tag g3-warm  --store reuse --warm "${ENV[@]}" --receive all ;;
    nsys)  $D --repeat 1 --tag g4-nsys  --store reuse --warm --nsys "${ENV[@]}" --receive none ;;
    counters)
      for b in 26235156 24628607; do
        python3 scripts/rv64_m3_pod.py prove $b --gpus 2 --stream $S --tag g5-counters --counters --smaps \
          --reference $REF/$b-2gpu-scale/receipt.json "${ENV[@]}"
      done ;;
    scale)
      python3 scripts/rv64_m3_pod.py bench 24697070 --gpus 2 --stream $S --tag g6-scale --allow-scale-up \
        --reference $REF/24697070-2gpu-scale/receipt.json "${ENV[@]}" ;;
  esac
  echo "STEP $s done $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
done
echo GATE_DONE
