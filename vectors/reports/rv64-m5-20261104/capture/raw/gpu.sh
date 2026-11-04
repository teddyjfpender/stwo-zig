#!/bin/bash
set -uo pipefail
cd /workspace/m3/src/m5-capture
S=m5-capture
REF=/workspace/m3/runs/integrate
ENV=(--env STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1 --env STWO_RV64_GPU_CPU_REPLAY=1 --env STWO_RV64_CORE_SINGLE_STREAM=1 --env STWO_RV64_DEVICE_ARENA=1)
run() { b=$1; tag=$2; shift 2; echo "RUN $b $tag start $(date -u +%T) load $(cut -d" " -f1 /proc/loadavg)"; python3 scripts/rv64_m3_pod.py bench $b --gpus 2 --stream $S --tag $tag --reference $REF/$b-2gpu-scale/receipt.json "${ENV[@]}" "$@" 2>&1 | tail -4; echo "RUN $b $tag rc=${PIPESTATUS[0]} $(date -u +%T)"; }
run 26235156 v6
run 24628607 v6
run 24628607 v6-i8 --capture-inflight 8
echo GPU_DONE
