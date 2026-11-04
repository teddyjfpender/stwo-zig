#!/bin/bash
# diet-wire: named outer profile runs on the diet-wire build. bash prof.sh TAGSUFFIX "156:PROFILE 607:PROFILE ..." (PROFILE=r1 for control)
set -u
cd /workspace/m3/src/m6-diet-wire
B=/workspace/m3/build/m6-diet-wire; R=/workspace/m3/runs/m6-diet-wire
sfx=$1; shift
for item in $1; do
  b=${item%%:*}; p=${item##*:}; [ $b = 156 ] && b=26235156; [ $b = 607 ] && b=24628607
  case $p in k3) P=m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1;; k4c) P=m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1;; *) P=r1_b2_q108_p20_fold4;; esac
  tag=$p-$sfx
  echo "RUN $b $P tag=$tag start $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
  STWO_RV64_OUTER_PROFILE=$P python3 scripts/rv64_m3_pod.py bench $b --gpus 2 --stream m6-diet-wire --tag $tag \
    --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --library /workspace/m3/build/m5-integrate/cuda/native/libstwo-rv64-native.so \
    --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver --env STWO_RV64_OUTER_PROFILE=$P > $R/$tag-$b.log 2>&1
  echo "RUN $b $P exit=$? end $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
done
echo PROF_DONE
