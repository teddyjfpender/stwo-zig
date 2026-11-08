#!/bin/bash
# m8-gn-node gate pipeline. usage: gates.sh <source-commit> <run-name> <addon-build-name> <arms...>
# arms: d-<block> default | r-<block> recorder (OUTER_JOBS=1 + DEVICE_CHECKS=1 + GN_NODE_RECORD)
#       g-<block> gn-node check (OUTER_JOBS=1 + DEVICE_CHECKS=1 + GN_NODE=check + graph threshold 1)
set -u
SC=$1; N=$2; AB=$3; shift 3
S=m8-gn-node
R=/workspace/m3/runs/$S/$N
B=/workspace/m3/build/$S
ADDON=$B/jobs-addon-$AB/libstwo-rv64-jobs.so
FS=/workspace/m3/build/m8-feeder/assets/libstwo-rv64-outer-fs-ops.so
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global TMPDIR=/workspace/m3/tmp
mkdir -p $R; L=$R/pipeline.log
log(){ echo "$* $(date -u +%FT%TZ)" >> $L; }
cd /workspace/m3/src/$S
sha256sum $ADDON $FS >> $L
LIBS="--env STWO_RV64_M8_JOBS_LIBRARY=$ADDON --env STWO_RV64_M8_OUTER_FS_LIBRARY=$FS --env STWO_RV64_M8_JOBS_PINNED_BYTES=2365587456"
G="bash scripts/rv64_gate.sh --stream $S --source-commit $SC"
for ARM in "$@"; do
  log STEP gate-$ARM
  rm -rf /workspace/m3/runs/$S/daemon-*-r2-gate-gate-$ARM-00-baseline  # this stream only
  case $ARM in
    d-*) $G --out $R/gate-$ARM --block ${ARM#d-} > $R/gate-$ARM.log 2>&1 ;;
    r-*) mkdir -p $R/rec-${ARM#r-}; $G --out $R/gate-$ARM --block ${ARM#r-} --env STWO_RV64_M8_OUTER_JOBS=1 $LIBS --env STWO_RV64_M8_OUTER_DEVICE_CHECKS=1 --env STWO_RV64_M8_GN_NODE_RECORD=$R/rec-${ARM#r-} > $R/gate-$ARM.log 2>&1 ;;
    g-*) $G --out $R/gate-$ARM --block ${ARM#g-} --env STWO_RV64_M8_OUTER_JOBS=1 $LIBS --env STWO_RV64_M8_OUTER_DEVICE_CHECKS=1 --env STWO_RV64_M8_GN_NODE=check --env STWO_RV64_M8_OUTER_GRAPH_THRESHOLD=1 > $R/gate-$ARM.log 2>&1 ;;
    n-*) X=${ARM#n-}; $G --out $R/gate-$ARM --block ${X%-*} --env STWO_RV64_M8_OUTER_JOBS=1 $LIBS --env STWO_RV64_M8_OUTER_DEVICE_CHECKS=1 --env STWO_RV64_M8_GN_NODE=check --env STWO_RV64_M8_FAULT_INJECTION=1 --env STWO_RV64_M8_GN_NODE_FAULT_ORDINAL=${X#*-} > $R/gate-$ARM.log 2>&1 ;;
  esac
  log gate-$ARM EXIT $?
done
log DONE
