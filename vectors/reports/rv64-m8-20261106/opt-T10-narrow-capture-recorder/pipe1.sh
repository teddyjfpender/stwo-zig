#!/bin/bash
# T10 pipeline: wait for both GPUs < 2 GB used and >= 2 GB free disk, then gates (flag off 26235156; flag on 24628607 + 26235156)
# and the canonical 3+3 A/B on 24628607 (one image = default runtime; arms differ only by STWO_RV64_M8_CAPTURE_RECORDER).
# Usage (pod, tmux): C=<commit> bash pipe1.sh
S=m8-opt-T10-narrow-capture-recorder; R=/workspace/m3/runs/$S; SRC=/workspace/m3/src/$S; B=/workspace/m3/build/$S
C=${C:?commit}; ST=$R/pipe1.status; FLAG=STWO_RV64_M8_CAPTURE_RECORDER
RT=$SRC/design/riscv-proving-stack/m7-handoff/p0-runtime.json
log() { echo "$(date -u +%FT%TZ) $*" >> $ST; }
log start commit=$C
log waiting-for-gpus-and-disk
while true; do
  u=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | sort -n | tail -1)
  f=$(df --output=avail -B1G /workspace | tail -1 | tr -d ' ')
  [ "$u" -lt 2048 ] && [ "$f" -ge 2 ] && break; sleep 60
done
log gpus-free used=${u}MiB disk=${f}G
cd $SRC
bash scripts/rv64_gate.sh --stream $S --block 26235156 --out $R/gate-1-off-26235156 --source-commit $C > $R/gate-1-off-26235156.log 2>&1
rc=$?; log gate-off-26235156 rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
for blk in 24628607 26235156; do
  bash scripts/rv64_gate.sh --stream $S --block $blk --out $R/gate-1-on-$blk --source-commit $C --env $FLAG=1 > $R/gate-1-on-$blk.log 2>&1
  rc=$?; log gate-on-$blk rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
done
rm -rf $SRC/.zig-cache $SRC/src/integrations/riscv_cuda/.zig-cache
get() { python3 -c "import json,sys;print(json.load(open('$RT'))['assets'][sys.argv[1]])" $1; }
python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $C \
  --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
  --library $(get library) --sparse $(get sparse) --observer $(get observer) --process-budget-guard $(get process_budget_guard) \
  --native-hooks-commit c72b51646 --device-hooks-commit c72b51646 \
  --preset $SRC/vectors/reports/rv64-m8-20261106/opt-T10-narrow-capture-recorder/ab-preset.json --block 24628607 \
  --out $R/ab-24628607-manifest.json > $R/ab-prepare.log 2>&1; log prepare rc=$?
python3 scripts/rv64_m7_integration_stack.py run --manifest $R/ab-24628607-manifest.json --out $R/ab-24628607 > $R/ab-24628607.log 2>&1
log ab-24628607 rc=$?
log DONE
