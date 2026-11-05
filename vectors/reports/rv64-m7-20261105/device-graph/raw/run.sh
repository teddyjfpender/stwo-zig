#!/bin/bash
set -euo pipefail
cd /workspace/m3/src/m7-device-graph
S=m7-device-graph
LIB=/workspace/m3/build/m6-integrate/cuda/native/libstwo-rv64-native.so
RECEIVER=/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver
for mode in 0 1; do
  python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream "$S" --repeat 3 --tag "enqueue-${mode}" --store none --receive first --library "$LIB" --receiver "$RECEIVER" --env "STWO_RV64_COMPOSITION_ENQUEUE=$mode"
done
python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream "$S" --repeat 2 --tag lanes2-22g --store none --receive first --library "$LIB" --receiver "$RECEIVER" --env STWO_RV64_RECURSION_LANES_PER_DEVICE=2 --env STWO_RV64_DEVICE_ARENA=22G
