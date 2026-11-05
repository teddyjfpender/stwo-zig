#!/bin/bash
# M7 leaf tape qualification. Producer commands acquire the shared GPU lock.
set -euo pipefail
cd /workspace/m3/src/m7-integrate
R=/workspace/m3/runs/m7-integrate
BASE=$R/daemon-26235156-24628607-r3-takeover-m6-control/receipt.json
LIB=/workspace/m3/build/m6-integrate/cuda/native/libstwo-rv64-native.so
RECEIVER=/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver
# The byte-neutral driver can be tested with the unchanged M6 receiver while
# the new receiver compiles. Pin its path so a concurrent install cannot race it.
while ! test -x /workspace/m3/build/m7-integrate/zig-out/bin/rv64-word16-ethereum-gpu-combined; do
  if grep -q '^EXIT=' "$R/leaf-build.log"; then grep -q '^EXIT=0$' "$R/leaf-build.log"; fi
  sleep 3
done
date -u
cat /proc/loadavg
sha256sum src/integrations/riscv_cpu/rv64_recursion/om31_native/{leaf_tape,leaf_graph,fold_tape,execution_wrap}.zig > "$R/leaf-source-sha256.txt"
python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream m7-integrate \
  --library "$LIB" --receiver "$RECEIVER" --repeat 2 --tag leaf-check-v1 --store none --receive none \
  --env STWO_RV64_LEAF_SEED_TAPE=check --env STWO_RV64_OUTER_PP_CLASS_CACHE=check \
  --env STWO_RV64_OUTER_PLAN_CLASS_CACHE=check
python3 scripts/rv64_m7_pair.py "$BASE" "$R/daemon-26235156-24628607-r2-leaf-check-v1/receipt.json" \
  --out "$R/leaf-check-v1-parity.json"
python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream m7-integrate \
  --library "$LIB" --receiver "$RECEIVER" --repeat 3 --tag leaf-on-v1 --store none --receive first \
  --env STWO_RV64_LEAF_SEED_TAPE=1
python3 scripts/rv64_m7_pair.py "$BASE" "$R/daemon-26235156-24628607-r3-leaf-on-v1/receipt.json" \
  --out "$R/leaf-on-v1-parity.json"
date -u
cat /proc/loadavg
echo LEAF_GATE_DONE
