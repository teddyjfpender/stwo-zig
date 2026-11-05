#!/bin/bash
# diet-wire A/B: fold arity k on the M5 integrate binaries (same driver/library/receiver), one-shot bench, dev blocks only.
#   bash ab.sh TAGSUFFIX "156:3 156:2 607:3 607:2"
set -u
cd /workspace/m3/src/m6-diet-wire
B=/workspace/m3/build/${BUILD:-m5-integrate}; R=/workspace/m3/runs/m6-diet-wire
RECV=${RECV:-$B/receiver-v2/bin/rv64-word16-ethereum-recursion-receiver}
[ -x "$RECV" ] || RECV=$B/zig-out/bin/rv64-word16-ethereum-recursion-receiver
sfx=$1; shift
for item in $1; do
  b=${item%%:*}; k=${item##*:}; [ $b = 156 ] && b=26235156; [ $b = 607 ] && b=24628607
  tag=k$k-$sfx
  echo "RUN $b k=$k tag=$tag start $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
  STWO_RV64_FOLD_ARITY=$k python3 scripts/rv64_m3_pod.py bench $b --gpus 2 --stream m6-diet-wire --tag $tag \
    --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --library $B/cuda/native/libstwo-rv64-native.so \
    --receiver $RECV --env STWO_RV64_FOLD_ARITY=$k ${EXTRA:-} > $R/$tag-$b.log 2>&1
  echo "RUN $b k=$k exit=$? end $(date -u +%T) load $(cut -d' ' -f1 /proc/loadavg)"
done
echo AB_DONE
