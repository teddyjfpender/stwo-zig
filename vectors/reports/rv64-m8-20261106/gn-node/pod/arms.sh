#!/bin/bash
# gn-node in-service check arms (proof-only runner). usage: arms.sh <addon-build> <arm...>; arm = g-<block> | n-<block>-<ordinal> | r-<block>
set -u
AB=$1; shift
R=/workspace/m3/runs/m8-gn-node
A=/workspace/m3/build/m8-gn-node/jobs-addon-$AB/libstwo-rv64-jobs.so
FS=/workspace/m3/build/m8-feeder/assets/libstwo-rv64-outer-fs-ops.so
BASE="STWO_RV64_M8_OUTER_JOBS=1 STWO_RV64_M8_JOBS_LIBRARY=$A STWO_RV64_M8_OUTER_FS_LIBRARY=$FS STWO_RV64_M8_JOBS_PINNED_BYTES=2365587456 STWO_RV64_M8_OUTER_DEVICE_CHECKS=1"
cd /workspace/m3/src/m8-gn-node
for ARM in "$@"; do
  case $ARM in
    g-*) B=${ARM#g-}; python3 $R/gn_prove.py $R/arm-$ARM $B $BASE STWO_RV64_M8_GN_NODE=check STWO_RV64_M8_OUTER_GRAPH_THRESHOLD=1 > $R/arm-$ARM.log 2>&1 ;;
    j-*) B=${ARM#j-}; python3 $R/gn_prove.py $R/arm-$ARM $B $BASE STWO_RV64_M8_GN_NODE=job STWO_RV64_M8_OUTER_GRAPH_THRESHOLD=1 > $R/arm-$ARM.log 2>&1 ;;
    n-*) X=${ARM#n-}; B=${X%-*}; O=${X#*-}; python3 $R/gn_prove.py $R/arm-$ARM $B $BASE STWO_RV64_M8_GN_NODE=check STWO_RV64_M8_FAULT_INJECTION=1 STWO_RV64_M8_GN_NODE_FAULT_ORDINAL=$O > $R/arm-$ARM.log 2>&1 ;;
  esac
  echo "$ARM EXIT=$?" >> $R/arms.status
done
echo DONE >> $R/arms.status
