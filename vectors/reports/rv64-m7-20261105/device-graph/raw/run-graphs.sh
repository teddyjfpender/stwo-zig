#!/bin/bash
set -euo pipefail
cd /workspace/m3/src/m7-device-graphs
LIB=/workspace/m3/build/m7-device-graphs/cuda/native/libstwo-rv64-native.so
RECEIVER=/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver
for mode in 1 0; do
 python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream m7-device-graphs --repeat 3 --tag "graphs-${mode}-22g" --store none --receive first --library "$LIB" --receiver "$RECEIVER" --env "STWO_RV64_ASSIGNMENT_GRAPHS=$mode" --env STWO_RV64_DEVICE_ARENA=22G --env STWO_RV64_RECURSION_LANE_SESSIONS=0
 done
