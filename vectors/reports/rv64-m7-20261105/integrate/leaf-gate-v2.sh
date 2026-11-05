#!/bin/bash
set -euo pipefail
cd /workspace/m3/src/m7-integrate
R=/workspace/m3/runs/m7-integrate
BASE=$R/daemon-26235156-24628607-r3-takeover-m6-control/receipt.json
LIB=/workspace/m3/build/m6-integrate/cuda/native/libstwo-rv64-native.so
REC=/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver
DRIVER=/workspace/m3/build/m7-integrate/zig-out/bin/rv64-word16-ethereum-gpu-combined
OLD=1140fe8fc57764fdf366c67c3b28c29ad3ae86643dac2155ea34af7d6e338dec
test "$(sha256sum "$DRIVER" | cut -d' ' -f1)" != "$OLD"
date -u
cat /proc/loadavg
sha256sum src/integrations/riscv_cpu/rv64_recursion/om31_native/{leaf_tape,leaf_graph,fold_tape,execution_wrap,outer_wrap}.zig \
  src/integrations/circuit_cpu/om31/{cache_pack,device_prove,mod}.zig \
  src/integrations/riscv_cuda/rv64/{outer_assignment,outer_source}.zig > "$R/leaf-v2-source-sha256.txt"
python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream m7-integrate \
  --library "$LIB" --receiver "$REC" --repeat 2 --tag leaf-check-v2 --store none --receive none \
  --env STWO_RV64_LEAF_SEED_TAPE=check --env STWO_RV64_OUTER_PP_CLASS_CACHE=check \
  --env STWO_RV64_OUTER_PLAN_CLASS_CACHE=check
python3 scripts/rv64_m7_pair.py "$BASE" "$R/daemon-26235156-24628607-r2-leaf-check-v2/receipt.json" \
  --out "$R/leaf-check-v2-parity.json"
python3 scripts/rv64_m4_resident.py daemon 26235156 24628607 --stream m7-integrate \
  --library "$LIB" --receiver "$REC" --repeat 3 --tag leaf-on-v2 --store none --receive first \
  --env STWO_RV64_LEAF_SEED_TAPE=1
python3 scripts/rv64_m7_pair.py "$BASE" "$R/daemon-26235156-24628607-r3-leaf-on-v2/receipt.json" \
  --out "$R/leaf-on-v2-parity.json"
date -u
cat /proc/loadavg
echo LEAF_V2_GATE_DONE
