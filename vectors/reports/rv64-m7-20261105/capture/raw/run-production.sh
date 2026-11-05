#!/bin/bash
set -euo pipefail
cd /workspace/m3/src/m7-capture
LIB=/workspace/m3/build/m6-integrate/cuda/native/libstwo-rv64-native.so
for mode in 0 1; do
  python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream m7-capture --repeat 3 --tag "capture-views-${mode}" --store none --receive first --library "$LIB" --env "STWO_RV64_IMAGE_PROGRAM_CACHE=$mode" --env "STWO_RV64_CAPTURE_PROGRAM_VIEW=$mode"
done
