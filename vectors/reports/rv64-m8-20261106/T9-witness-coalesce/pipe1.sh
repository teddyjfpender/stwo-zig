#!/bin/bash
# T9 pipeline 1 (pod): image -> wait for free GPUs -> gate flag off (26235156) -> gates flag on (26235156, 24628607)
# -> canonical 3+3 A/B on 24628607 (one image, both arms the default fullstack, only STWO_RV64_M8_WITNESS_COALESCE differs).
set -u
S=m8-opt-T9-witness-coalesce; R=/workspace/m3/runs/$S; SRC=/workspace/m3/src/$S; B=/workspace/m3/build/$S; RT=$B/img1/runtime.json
C=${C:?commit}; ST=$R/pipe1.status; FLAG=STWO_RV64_M8_WITNESS_COALESCE
log() { echo "$(date -u +%FT%TZ) $*" >> $ST; }
log start commit=$C
until grep -q "^EXIT" $R/img1.log 2>/dev/null; do sleep 30; done
grep -q "^EXIT 0" $R/img1.log || { log img1-failed; exit 1; }
log img1 $(grep -v EXIT $R/img1.log | tail -1)
# Keep only the linked image: the recompiled objects are recorded by sha in build.json.
rm -f $B/img1/*.cu.o
log waiting-for-gpus-and-3GB-disk
while true; do
  u=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | sort -n | tail -1)
  # The gate's zig build + service runs need ~1 GB; do not fill the shared disk.
  free=$(df -BG --output=avail /workspace | tail -1 | tr -dc 0-9)
  [ "$u" -lt 2048 ] && [ "$free" -ge 3 ] && break; sleep 30
done
log gpus-free
cd $SRC
bash scripts/rv64_gate.sh --stream $S --block 26235156 --out $R/gate-1-off-26235156 --source-commit $C --runtime $RT > $R/gate-1-off-26235156.log 2>&1
rc=$?; log gate-off-26235156 rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
for blk in 26235156 24628607; do
  bash scripts/rv64_gate.sh --stream $S --block $blk --out $R/gate-1-on-$blk --source-commit $C --runtime $RT --env $FLAG=1 > $R/gate-1-on-$blk.log 2>&1
  rc=$?; log gate-on-$blk rc=$rc; [ $rc -eq 0 ] || { log STOP; exit 1; }
done
get() { python3 -c "import json,sys;print(json.load(open('$RT'))['assets'][sys.argv[1]])" $1; }
python3 scripts/rv64_m7_integration_stack.py prepare --source-root $SRC --source-commit $C \
  --driver $B/zig-out/bin/rv64-word16-ethereum-gpu-combined --receiver $B/zig-out/bin/rv64-word16-ethereum-recursion-receiver \
  --library $(get library) --sparse $(get sparse) --observer $(get observer) --process-budget-guard $(get process_budget_guard) \
  --native-hooks-commit c72b51646 --device-hooks-commit c72b51646 \
  --preset $SRC/vectors/reports/rv64-m8-20261106/T9-witness-coalesce/ab-preset.json --block 24628607 \
  --out $R/ab-24628607-manifest.json > $R/ab-prepare.log 2>&1; log prepare rc=$?
python3 scripts/rv64_m7_integration_stack.py run --manifest $R/ab-24628607-manifest.json --out $R/ab-24628607 > $R/ab-24628607.log 2>&1
log ab-24628607 rc=$?
log DONE
