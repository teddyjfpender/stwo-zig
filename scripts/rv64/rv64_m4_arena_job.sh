#!/bin/bash
# arena_job.sh MODE BLOCK TAG LIB [K=V ...]   MODE = prove|bench
set -u
MODE=$1; BLOCK=$2; TAG=$3; LIB=$4; shift 4
SRC=/workspace/m3/src/m4-arena
BASE=/workspace/m3/build/m4-arena/base
OUT=/workspace/m3/runs/m4-arena/reports; mkdir -p $OUT
ENVS=(--env STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1 --env STWO_RV64_GPU_CPU_REPLAY=1 --env STWO_RV64_CORE_SINGLE_STREAM=1)
for kv in "$@"; do ENVS+=(--env "$kv"); done
LOAD=$(cut -d' ' -f1 /proc/loadavg)
echo "START $(date +%T) $MODE $BLOCK $TAG load1=$LOAD lib=$LIB $*"
cd $SRC && python3 scripts/rv64_m3_pod.py $MODE $BLOCK --gpus 2 --stream m4-arena --tag $TAG \
  --driver $BASE/rv64-word16-ethereum-gpu-combined --library $LIB --receiver $BASE/rv64-word16-ethereum-recursion-receiver "${ENVS[@]}"
RC=$?
RUN=/workspace/m3/runs/m4-arena/$BLOCK-2gpu-$TAG
python3 scripts/rv64_m4_arena_report.py $RUN --block $BLOCK --label $TAG --out $OUT/$TAG.json \
  --baseline $SRC/vectors/reports/rv64-m3-20261104/integrate/scale/$BLOCK.json --load1 $LOAD --notes "$*"
echo "END $(date +%T) rc=$RC"
